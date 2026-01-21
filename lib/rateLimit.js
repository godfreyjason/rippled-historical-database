const config = require('../config');
const hbase = require('./hbase');
const Logger = require('./logger');
const Limiter = require('ratelimiter');
const Redis = require('redis');

const log = new Logger({
  scope: 'rate-limit',
  file: config.get('logFile'),
  level: config.get('logLevel')
});

// Optimization: Use a constant for interval to avoid magic numbers
const UPDATE_INTERVAL = 10 * 60 * 1000;
const limits = {
  max: undefined,
  duration: undefined,
  whitelist: new Set(), // Optimization: Using Set for O(1) lookup time
  blacklist: new Set()
};

let redisClient;

/**
 * Initialize Redis connection with robust error handling
 */
if (config.get('rateLimit')) {
  redisClient = Redis.createClient({
    host: config.get('redis:host'),
    port: config.get('redis:port'),
    retry_strategy: (options) => {
      // Security: Exponential backoff to prevent overwhelming Redis during recovery
      return Math.min(options.attempt * 100, 3000);
    }
  });

  redisClient.on('error', (err) => log.error('Redis Error:', err));
}

[Image of a rate limiting system using Redis and sliding window algorithm]

/**
 * updateConfig: Fetches rate limit rules from HBase and updates local cache
 */
function updateConfig() {
  hbase.getRow({
    table: 'control',
    rowkey: 'rate_limit'
  }, (err, resp) => {
    if (err) {
      log.error('HBase Config Fetch Error:', err);
      return;
    }

    if (resp && resp.max && resp.duration) {
      limits.max = parseInt(resp.max, 10);
      limits.duration = parseInt(resp.duration, 10);

      try {
        // Optimization: Parsing into Sets for significantly faster inclusion checks
        const white = resp.whitelist ? JSON.parse(resp.whitelist) : [];
        const black = resp.blacklist ? JSON.parse(resp.blacklist) : [];
        
        limits.whitelist = new Set(white);
        limits.blacklist = new Set(black);
      } catch (e) {
        log.error('Config Parse Error:', e);
      }

      log.info(`Rate Limits Updated: ${limits.max} req / ${limits.duration / 1000}s. ` +
               `W: ${limits.whitelist.size}, B: ${limits.blacklist.size}`);
    } else {
      limits.max = undefined;
      log.info('No active rate limits found in configuration');
    }
  });
}

// Start periodic sync
if (config.get('rateLimit')) {
  setInterval(updateConfig, UPDATE_INTERVAL);
  updateConfig();
}

/**
 * middleware: The main gatekeeper for incoming HTTP requests
 */
module.exports.middleware = function(req, res, next) {
  // Security: Trusting 'fastly-client-ip' only if your infra is correctly behind Fastly
  const ip = req.headers['fastly-client-ip'] || req.ip;

  // Fail-safe: If rate limiting is disabled or Redis is down, allow request
  if (!limits.max || !ip || !redisClient || !redisClient.connected) {
    return next();
  }

  // O(1) Blacklist Check
  if (limits.blacklist.has(ip)) {
    return res.status(403).send({ error: 'Access denied: IP blacklisted' });
  }

  // O(1) Whitelist Check
  if (limits.whitelist.has(ip)) {
    return next();
  }

  const limiter = new Limiter({
    max: limits.max,
    duration: limits.duration,
    id: ip,
    db: redisClient
  });

  limiter.get((err, limit) => {
    if (err) {
      log.error('Limiter Runtime Error:', err);
      return next(); // Fail-open on error for better UX
    }

    // Set standard rate limit headers
    res.set({
      'X-RateLimit-Limit': limit.total,
      'X-RateLimit-Remaining': Math.max(0, limit.remaining - 1),
      'X-RateLimit-Reset': limit.reset
    });

    if (limit.remaining > 0) {
      return next();
    }

    const retryAfter = Math.ceil(limit.reset - (Date.now() / 1000));
    res.set('Retry-After', retryAfter);
    
    log.warn(`Rate limit exceeded for IP: ${ip}`);
    res.status(429).send({
      error: `Too many requests. Please retry in ${retryAfter} seconds.`
    });
  });
};

module.exports.updateConfig = updateConfig;
