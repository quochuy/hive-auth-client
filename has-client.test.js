const CryptoJS = require('crypto-js');

const { HasClient } = require('./has-client');

jest.useFakeTimers();
jest.spyOn(global, 'setTimeout');

test('Constructor sets parameters', () => {
  let client = new HasClient('myhost');
  expect(client.config).toEqual({
    host: 'wss://myhost/',
    auth_key_secret: '',
  });
  expect(client.debug).toBe(false);

  client = new HasClient('myhost', 'mysecret', true);
  expect(client.config).toEqual({
    host: 'wss://myhost/',
    auth_key_secret: 'mysecret',
  });
  expect(client.debug).toBe(true);
  expect(client.timeout).toBe(60000);
});

test('Adds, calls and removes event handlers', () => {
  const client = new HasClient('myhost', '', false);
  const successHandler = jest.fn();
  const failureHandler = jest.fn();

  client.addEventHandler('AuthSuccess', successHandler);
  client.addEventHandler('AuthFailure', failureHandler);
  client.dispatchEvent('AuthSuccess', { data: 'test' });
  expect(successHandler).toHaveBeenCalledWith({ data: 'test' });
  expect(failureHandler).not.toHaveBeenCalled();

  successHandler.mockClear();
  failureHandler.mockClear();
  client.removeEventHandler('AuthSuccess', successHandler);
  client.dispatchEvent('AuthSuccess', { data: 'test' });
  client.dispatchEvent('AuthFailure', { data: 'test' });
  expect(successHandler).not.toHaveBeenCalled();
  expect(failureHandler).toHaveBeenCalledWith({ data: 'test' });
})

test('Expires timeout does execute and clear expire timeout does work', () => {
  const client = new HasClient('myhost');
  client.currentRequestExpire = new Date().getTime() + 2500;

  const expireHandler = jest.fn();
  client.addEventHandler('RequestExpired', expireHandler);
  client.setExpireTimeout();
  expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 2500);
  jest.runAllTimers();
  expect(expireHandler).toHaveBeenCalledWith({ message: 'expired' });

  expireHandler.mockClear();
  client.currentRequestExpire = new Date().getTime() + 2500;
  client.setExpireTimeout();
  expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 2500);
  client.clearExpireTimeout();
  jest.runAllTimers();
  expect(expireHandler).not.toHaveBeenCalled();
});

test('Processes websocket messages', () => {
  const client = new HasClient('myhost', '', false);
  client.dispatchEvent = jest.fn();

  let message = '{"cmd": "connected", "protocol": 0.8, "timeout": 120}';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('ConnectionSuccess', { message: JSON.parse(message) });
  expect(client.timeout).toBe(120000);

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "connected", "protocol": 0.9 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('ConnectionFailure', { message: JSON.parse(message) });

  client.dispatchEvent.mockClear();
  client.authKey = 'abcde';
  message = '{ "cmd": "auth_wait", "protocol": 0.8, "uuid": "myuuid", "expire": 1234 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('AuthPending', {
    ...JSON.parse(message),
    key: client.authKey,
  });

  client.dispatchEvent.mockClear();
  client.authKey = 'abcde';
  let data = { test: 'test', token: 'mytoken', expire: 6789 };
  let encryptedData = CryptoJS.AES.encrypt(JSON.stringify(data), client.authKey);
  message = {
    cmd: "auth_ack",
    protocol: 0.8,
    uuid: "myuuid",
    expire: 1234,
    data: encryptedData.toString(),
  };
  client.processWebsocketMessage({ data: JSON.stringify(message) });
  expect(client.dispatchEvent).toHaveBeenCalledWith('AuthSuccess', {
    ...message,
    data,
    authData: {
      token: data.token,
      key: client.authKey,
      expire: data.expire,
    }
  });

  client.dispatchEvent.mockClear();
  client.authKey = 'abcde';
  client.uuid = 'myuuid2';
  data = 'myuuid2';
  encryptedData = CryptoJS.AES.encrypt(data, client.authKey);
  message = {
    cmd: "auth_nack",
    protocol: 0.8,
    uuid: "myuuid",
    expire: 1234,
    data: encryptedData.toString(),
  };
  client.processWebsocketMessage({ data: JSON.stringify(message) });
  expect(client.dispatchEvent).toHaveBeenCalledWith('AuthFailure', { message });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "attach_ack", "protocol": 0.8 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('AttachSuccess', { message: JSON.parse(message) });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "attach_nack", "protocol": 0.8 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('AttachFailure', { message: JSON.parse(message) });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "auth_err", "protocol": 0.8 }'
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('Error', { message: JSON.parse(message) });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "error", "protocol": 0.8 }'
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('Error', { message: JSON.parse(message) });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "sign_wait", "protocol": 0.8, "uuid": "myuuidsign_wait", "expire": 213124 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('SignPending', { message: JSON.parse(message) });
  expect(client.uuid).toBe('myuuidsign_wait');
  expect(client.currentRequestExpire).toBe(213124);

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "sign_ack", "protocol": 0.8 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('SignSuccess', { message: JSON.parse(message) });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "sign_nack", "protocol": 0.8, "error": "myerror" }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('SignFailure', { message: 'myerror' });

  client.dispatchEvent.mockClear();
  client.authKey = 'abcde';
  client.uuid = 'myuuid3';
  data = '{"error": "signerror"}';
  encryptedData = CryptoJS.AES.encrypt(data, client.authKey);
  message = {
    cmd: "sign_err",
    protocol: 0.8,
    uuid: "myuuid",
    expire: 1234,
    error: encryptedData.toString(),
  };
  client.processWebsocketMessage({ data: JSON.stringify(message) });
  expect(client.dispatchEvent).toHaveBeenCalledWith('Error', { error: 'signerror' });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "challenge_wait", "protocol": 0.8, "uuid": "myuuidchallenge_wait", "expire": 7556456 }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('ChallengePending', { message: JSON.parse(message) });
  expect(client.uuid).toBe('myuuidchallenge_wait');
  expect(client.currentRequestExpire).toBe(7556456);

  client.dispatchEvent.mockClear();
  client.authKey = 'abcde';
  client.uuid = 'myuuid4';
  data = '{"challenge": "challengedata"}';
  encryptedData = CryptoJS.AES.encrypt(data, client.authKey);
  message = {
    cmd: "challenge_ack",
    protocol: 0.8,
    uuid: "myuuid",
    expire: 1234,
    data: encryptedData.toString(),
  };
  client.processWebsocketMessage({ data: JSON.stringify(message) });
  expect(client.dispatchEvent).toHaveBeenCalledWith('ChallengeSuccess', {
    ...message,
    data: {
      challenge: 'challengedata',
    },
  });

  client.dispatchEvent.mockClear();
  message = '{ "cmd": "challenge_nack", "protocol": 0.8, "error": "challengefailed" }';
  client.processWebsocketMessage({ data: message });
  expect(client.dispatchEvent).toHaveBeenCalledWith('ChallengeFailure', { message: 'challengefailed' });

  client.dispatchEvent.mockClear();
  client.authKey = 'abcde';
  client.uuid = 'myuuid5';
  data = 'challengerror';
  encryptedData = CryptoJS.AES.encrypt(data, client.authKey);
  message = {
    cmd: "challenge_err",
    protocol: 0.8,
    uuid: "myuuid",
    expire: 1234,
    error: encryptedData.toString(),
  };
  client.processWebsocketMessage({ data: JSON.stringify(message) });
  expect(client.dispatchEvent).toHaveBeenCalledWith('Error', { error: 'challengerror'});
});
