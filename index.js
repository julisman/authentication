/*
 * author : agung.julisman@yahoo.com
 *
 * */
'use strict'

const jwt = require('jwt-simple')
const moment = require('moment')

/**
 * Module exports.
 * @public
 */

module.exports = {
    version: '1.0.1',

    /**
     * Service fot method POST.
     *
     * @param  {String} url
     * @param  {Json} data
     * @return {Object} Callback status 'statusCode' and body 'response'
     */
    ensureAuthenticated: (req, res, next) => {
      if (!req.headers.authorization) {
          return res.status(401).send({ message: 'Please make sure your request has an Authorization header' });
      }
      let token = req.headers.authorization.split(' ')[1];

      let payload = null;
      try {
          payload = jwt.decode(token, process.env.TOKEN_SECRET);
      }
      catch (err) {
          return res.status(401).send({ message: 'invalid token' });
      }

      if (payload.exp <= moment().unix()) {
          return res.status(401).send({ message: 'Token has expired' });
      }
      if (payload.ip !== ( req.ip || req.ips) ) {
          // TODO: agungj: do something when user login with different ip
          return res.status(401).send({ message: 'invalid ip' });
      }
      /*
      if (payload.user_agent !== req.headers['user-agent'] ) {

          return res.status(401).send({ message: 'invalid user agent' });
      }*/
      req.user = payload.sub;
      next();
    },

    createJWT: (id, ip, userAgent) => {
      const payload = {
        sub: id,
        ip:ip,
        user_agent:userAgent,
        iat: moment().unix(),
        exp: moment().add(14, 'days').unix()
      }

      return jwt.encode(payload, process.env.TOKEN_SECRET)
    }
}



