const _ = require('lodash');
const CryptoJS = require('crypto-js');

const HAS_PROTOCOL = '0.8';
const HAS_DEFAULT_REQUEST_TIMEOUT = 60 * 1000;
const CMD = {
  CONNECTED: 'connected',
  AUTH_REQ: 'auth_req',
  AUTH_WAIT: 'auth_wait',
  AUTH_ACK: 'auth_ack',
  AUTH_NACK: 'auth_nack',
  AUTH_ERR: 'auth_err',
  SIGN_REQ: 'sign_req',
  SIGN_WAIT: 'sign_wait',
  SIGN_ACK: 'sign_ack',
  SIGN_NACK: 'sign_nack',
  SIGN_ERR: 'sign_err',
  CHALLENGE_REQ: 'challenge_req',
  CHALLENGE_WAIT: 'challenge_wait',
  CHALLENGE_ACK: 'challenge_ack',
  CHALLENGE_NACK: 'challenge_nack',
  CHALLENGE_ERR: 'challenge_err',
  ATTACH_REQ: 'attach_req',
  ATTACH_ACK: 'attach_ack',
  ATTACH_NACK: 'attach_nack',
  ERROR: 'error',
};

class HasClient {
  /**
   * Class constructor
   * @param {string} host
   * @param {string} auth_key_secret
   * @param {boolean} debug
   */
  constructor(host, auth_key_secret = '', debug = false) {
    this.websocket = undefined;
    this.websocketConnectionCheckDelay = 250;
    this.timeout = undefined;
    this.isConnected = false;
    this.debug = debug;
    this.config = {
      host: `wss://${host}/`,
      auth_key_secret: auth_key_secret,
    };
    this.eventHandlers = {
      AttachFailure: [],
      AttachSuccess: [],
      AuthPending: [],
      AuthSuccess: [],
      AuthFailure: [],
      SignPending: [],
      SignSuccess: [],
      SignFailure: [],
      SignError: [],
      ChallengePending: [],
      ChallengeSuccess: [],
      ChallengeFailure: [],
      ChallengeError: [],
      Error: [],
      RequestExpired: [],
    };
    this.messages = [];
    this.uuid = '';
    this.currentRequestExpire = undefined;
    this.expireCheckTimeoutId = undefined;
    this.authKey = '';
  }

  /**
   * Console.log wrapper
   */
  log() {
    const now = new Date().toLocaleString();

    if (typeof arguments.unshift === 'undefined') {
      // eslint-disable-next-line prefer-rest-params
      arguments[0] = `${now} HAS Client: ${arguments[0]}`;
    } else {
      arguments.unshift(now);
      arguments.unshift('HAS Client');
    }

    // eslint-disable-next-line prefer-rest-params
    console.log.apply(null, arguments);
  }

  /**
   * @callback eventHandler
   * @param {Object} event
   * @param {string} event.message
   */
  /**
   * Adds a handler function for HAS websocket message events
   * @param {string} eventName
   * @param {eventHandler} handlerFunction
   */
  addEventHandler(eventName, handlerFunction) {
    let eventNames = [];
    if (typeof eventName === 'string') {
      eventNames.push(eventName);
    } else {
      eventNames = [...eventName];
    }

    for (let ei = 0; ei < eventNames.length; ei += 1) {
      if (Object.prototype.hasOwnProperty.call(this.eventHandlers, eventNames[ei])) {
        this.eventHandlers[eventNames[ei]].push(handlerFunction);
      } else {
        this.log(`unknown event ${eventNames[ei]}`);
      }
    }
  }

  /**
   * @callback eventHandler
   * @param {Object} event
   * @param {string} event.message
   */
  /**
   * Removes a handler function for HAS websocket message events
   * @param {string} eventName
   * @param {eventHandler} handlerFunction
   */
  removeEventHandler(eventName, handlerFunction) {
    if (this.eventHandlers) {
      for (let hi = 0; hi < this.eventHandlers[eventName].length; hi += 1) {
        const handler = this.eventHandlers[eventName][hi];
        const matching = handler === handlerFunction;
        if (matching) {
          // Setting to null instead of deleting the element from the array
          // as this can break the loop from dispatchEvent() above
          this.eventHandlers[eventName][hi] = undefined;
        }
      }
    }
  };

  /**
   * Dispatch HAS websocket message events
   * @param {string} eventName
   * @param {Object} event
   * @param {string} event.message
   */
  dispatchEvent(eventName, event) {
    if (this.eventHandlers[eventName].length > 0) {
      this.log(`dispatching ${eventName} event${event.issuer ? ` issued by ${event.issuer}` : ''}`);

      for (let hi = 0; hi < this.eventHandlers[eventName].length; hi += 1) {
        const eventHandler = this.eventHandlers[eventName][hi];
        if (eventHandler !== null) {
          eventHandler(event);
        }
      }

      this.eventHandlers[eventName] = this.eventHandlers[eventName].filter((handler) => {
        return handler !== null;
      });
    }
  }

  /**
   * Clears the request expiry check timeout
   */
  clearExpireTimeout() {
    if (this.expireCheckTimeoutId) {
      clearTimeout(this.expireCheckTimeoutId);
    }
  }

  /**
   * Sets the request expiry check timeout
   */
  setExpireTimeout() {
    this.clearExpireTimeout();

    const now = new Date().getTime();
    let expireDiff = this.currentRequestExpire - now;
    if (expireDiff < 0) {
      expireDiff = 0;
    }

    this.expireCheckTimeoutId = setTimeout(() => {
      this.dispatchEvent('RequestExpired', { message: 'expired' });
    }, expireDiff);
  }

  processWebsocketMessage(event) {
    if(this.debug) this.log(`[RECV] ${event.data}`);
    const message = typeof (event.data) === 'string' ? JSON.parse(event.data) : event.data;
    let error;

    // Process HAS <-> App protocol
    if(message.cmd) {
      switch (message.cmd) {
        case CMD.CONNECTED:
          this.timeout = message.timeout * 1000;
          if(message.protocol > HAS_PROTOCOL) {
            console.error('HAS Client:unsupported HAS protocol');
          } else {
            this.log('has successfully connected');
          }
          break;

        case CMD.AUTH_WAIT:
          this.uuid = message.uuid;
          this.currentRequestExpire = message.expire;
          this.setExpireTimeout();

          this.dispatchEvent('AuthPending', {
            ...message,
            key: this.authKey,
          });
          break;

        case CMD.AUTH_ACK:
          try{
            let { data } = message;
            // Try to decrypt and parse payload data
            data = JSON.parse(CryptoJS.AES.decrypt(data, this.authKey).toString(CryptoJS.enc.Utf8));

            this.log(`auth_ack found: ${JSON.stringify(message)}`);
            this.dispatchEvent('AuthSuccess', {
              ...message,
              data,
              authData: {
                token: data.token,
                key: this.authKey,
                expire: data.expire,
              }
            });
          } catch(e) {
            // Decryption failed - ignore message
          }
          this.clearExpireTimeout();
          break;

        case CMD.AUTH_NACK:
          if (this.uuid === CryptoJS.AES.decrypt(message.data, this.authKey).toString(CryptoJS.enc.Utf8)) {
            this.dispatchEvent('AuthFailure', { message });
            this.clearExpireTimeout();
          }
          break;

        case CMD.ATTACH_ACK:
          this.dispatchEvent('AttachSuccess', message);
          this.clearExpireTimeout();
          break;

        case CMD.ATTACH_NACK:
          this.dispatchEvent('AttachFailure', message);
          this.clearExpireTimeout();
          break;

        case CMD.AUTH_ERR:
        case CMD.ERROR:
          this.dispatchEvent('Error', { message });
          this.clearExpireTimeout();
          break;

        case CMD.SIGN_WAIT:
          this.uuid = message.uuid;
          this.currentRequestExpire = message.expire;
          this.dispatchEvent('SignPending', { message });
          break;

        case CMD.SIGN_ACK:
          this.dispatchEvent('SignSuccess', { message });
          this.clearExpireTimeout();
          break;

        case CMD.SIGN_NACK:
          this.dispatchEvent('SignFailure', { message: message.error });
          this.clearExpireTimeout();
          break;

        case CMD.SIGN_ERR:
          error = CryptoJS.AES.decrypt(message.error, this.authKey).toString(CryptoJS.enc.Utf8);
          this.dispatchEvent('Error', { error });
          this.clearExpireTimeout();
          break;

        case CMD.CHALLENGE_WAIT:
          this.uuid = message.uuid;
          this.currentRequestExpire = message.expire;
          this.dispatchEvent('ChallengePending', { message });
          break;

        case CMD.CHALLENGE_ACK:
          try {
            let { data } = message;
            data = JSON.parse(CryptoJS.AES.decrypt(message.data, this.authKey).toString(CryptoJS.enc.Utf8))
            this.dispatchEvent('ChallengeSuccess', {
              ...message,
              data,
            });
            this.clearExpireTimeout();
          } catch(e) {
            // Decryption failed - ignore message
          }
          break;

        case CMD.CHALLENGE_NACK:
          this.dispatchEvent('ChallengeFailure', { message: message.error });
          this.clearExpireTimeout();
          break;

        case CMD.CHALLENGE_ERR:
          error = CryptoJS.AES.decrypt(message.error, this.authKey).toString(CryptoJS.enc.Utf8)
          this.dispatchEvent('Error', { error });
          this.clearExpireTimeout();
          break;

        default:
          console.log('Generic message', message);
          this.messages.push(message);
          break;
      }
    }
  }

  processWebsocketOpen(event) {
    // Web Socket is connected
    this.isConnected = true;
    if(this.debug) {
      this.log('WebSocket connected');
    }

    if (this.uuid) {
      this.attach();
    }
  }

  processWebsocketClose(event) {
    // connection closed, discard old websocket
    this.websocket = undefined;
    this.isConnected = false;
    this.log('HAS Client:WebSocket disconnected', event.code, event.wasClean);

    if (event.code === 1006 || event.wasClean === false) {
      setTimeout(async () => {
        await this.connect();
      }, 1000);
    }
  }

  /**
   * Open a new websocket connection if the browser supports it
   * @returns {boolean}
   */
  connectWebsocket() {
    if ("WebSocket" in window) {
      this.log('Connecting to ', this.config.host);
      this.websocket = new WebSocket(this.config.host);

      this.websocket.onopen = () => {
        this.processWebsocketOpen.apply(this, [event]);
      };

      this.websocket.onmessage = (event) => {
        this.processWebsocketMessage.apply(this, [event]);
      };

      this.websocket.onclose = (event) => {
        this.processWebsocketClose.apply(this, [event]);
      };

      return true;
    }

    return false;
  }

  /**
   * Attach a previous session to the new connection
   */
  attach() {
    if (typeof this.uuid !== 'string') {
      throw new Error('uuid has to be a string');
    }

    const payload = { cmd: CMD.ATTACH_REQ, uuid: this.uuid };
    this.send(JSON.stringify(payload));
    this.currentRequestExpire = new Date().getTime() + HAS_DEFAULT_REQUEST_TIMEOUT;
    this.setExpireTimeout();
  }

  /**
   * Promisified sleep helper
   * @param {number} ms
   * @returns {Promise<unknown>}
   */
  sleep(ms) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  /**
   * Wait until the websocket is ready
   * @TODO add max wait time
   * @returns {Promise<void>}
   */
  async waitForSocketConnection() {
    await this.sleep(this.websocketConnectionCheckDelay);
    if (this.websocket && this.websocket.readyState === 0) {
      await this.waitForSocketConnection();
    }
  }

  /**
   * Verifies the websocket is opened and connected else do it
   * @returns {Promise<boolean>}
   */
  async connect() {
    if (this.isConnected === false) {
      if (this.connectWebsocket()) {
        await this.waitForSocketConnection();
        this.log('IS NOW CONNECTED');
      }
    } else {
      console.log('Already connected');
    }

    return true;
  }

  /**
   * Asserts an object has required properties of valid types
   * @param {object} object
   * @param {string} objectName
   * @param {string[][]} requiredProperties
   */
  assert(object, objectName, requiredProperties) {
    if (!object) {
      throw new Error(`${objectName} is missing`);
    }

    if (Array.isArray(requiredProperties)) {
      if (requiredProperties.length === 0) {
        if (!Array.isArray(object)) {
          throw new Error(`${objectName} has to be an array`);
        } else if (object.length === 0) {
          throw new Error(`${objectName} can't be empty`);
        }
      } else {
        for (const requiredProperty of requiredProperties) {
          const [propertyName, propertyType] = requiredProperty;
          if (!_.has(object, propertyName)) {
            throw new Error(`${objectName}.${propertyName} is missing`);
          }

          const property = _.get(object, propertyName);
          // eslint-disable-next-line valid-typeof
          if (propertyType && typeof property !== propertyType) {
            throw new Error(`${objectName}.${propertyName} has to be a ${propertyType}`);
          }
        }
      }
    } else {
      if (!object) {
        throw new Error(`${objectName} has to be defined`);
      }
    }
  }

  /**
   * Sends messages to server via websocket
   * @param {string} message
   */
  async send(message) {
    await this.connect();

    this.log(`[SEND] ${message}`);
    this.websocket.send(message);
  }

  /**
   * Sends an authentication request to the server
   * @param {Object} authData
   * @param {string} authData.username
   * @param {string=} authData.token
   * @param {number=} authData.expire
   * @param {string=} authData.key
   * @param {Object} appData
   * @param {string} appData.name - Application name
   * @param {string} appData.description - Application description
   * @param {string} appData.icon - URL of application icon
   * @param {Object} challengeData
   * @param {string} challengeData.key_type
   * @param {Object} challengeData.challenge
   */
  authenticate(authData, appData, challengeData) {
    this.assert(authData, 'authData', [['username', 'string']]);
    this.assert(appData, 'appData', [['name', 'string']]);
    this.assert(challengeData, 'challengeData', [['key_type', 'string'], ['challenge', 'string']]);
    const gRand = () => {
      return Math.floor((1 + Math.random()) * 65536).toString(16).substring(1);
    };
    this.authKey = _.get(authData, 'key', `${gRand() + gRand()}-${gRand()}-${gRand()}-${gRand()}-${gRand()}${gRand()}${gRand()}`);
    const data = CryptoJS.AES.encrypt(JSON.stringify({ token: authData.token, app: appData, challenge: challengeData }), this.authKey).toString();
    const payload = {
      cmd: CMD.AUTH_REQ,
      account: authData.username,
      token: authData.token,
      data,
    };
    if(this.config.auth_key_secret) {
      // Encrypt auth_key before sending it to the HAS
      console.log('this.authKey', this.authKey);
      console.log('this.config', this.config);
      payload.auth_key = CryptoJS.AES.encrypt(this.authKey, this.config.auth_key_secret).toString();
    }

    this.send(JSON.stringify(payload));
    this.currentRequestExpire = new Date().getTime() + HAS_DEFAULT_REQUEST_TIMEOUT;
    this.setExpireTimeout();
  }

  /**
   * Sends a broadcast request to the server
   * @param {Object} authData
   * @param {string} authData.username
   * @param {string=} authData.token
   * @param {number=} authData.expire
   * @param {string=} authData.key
   * @param {string} keyType
   * @param {Array} ops
   */
  broadcast(authData, keyType, ops) {
    this.assert(authData, 'authData', [['username', 'string'], ['token', 'string'], ['key', 'string']]);
    this.assert(ops, 'ops', []);

    this.authKey = authData.key;
    const data = CryptoJS.AES.encrypt(JSON.stringify({ key_type: keyType, ops, broadcast: true }), authData.key).toString();
    const payload = { cmd: CMD.SIGN_REQ, account: authData.username, token: authData.token, data };
    this.send(JSON.stringify(payload));
    this.currentRequestExpire = new Date().getTime() + HAS_DEFAULT_REQUEST_TIMEOUT;
    this.setExpireTimeout();
  }

  /**
   * Sends a challenge request to the server
   * @param {Object} authData
   * @param {string} authData.username
   * @param {string=} authData.token
   * @param {number=} authData.expire
   * @param {string=} authData.key
   * @param {Object} challengeData
   * @param {string} challengeData.key_type
   * @param {Object} challengeData.challenge
   */
  challenge(authData, challengeData) {
    this.assert(authData, 'authData', [['username', 'string'], ['token', 'string'], ['key', 'string']]);
    this.assert(challengeData, 'challengeData', [['key_type', 'string'], ['challenge', 'string']]);

    this.authKey = authData.key;
    const data = CryptoJS.AES.encrypt(JSON.stringify(challengeData), authData.key).toString();
    const payload = { cmd: CMD.CHALLENGE_REQ, account:authData.username, token: authData.token, data };
    this.send(JSON.stringify(payload));
    this.currentRequestExpire = new Date().getTime() + HAS_DEFAULT_REQUEST_TIMEOUT;
    this.setExpireTimeout();
  }
}

module.exports = { HasClient };