function signIn(user: string, password: string, apiKey: string, session: Session) {
  // ruleid: node-secret-in-log
  console.log("signing in", user, password);

  // ruleid: node-secret-in-log
  logger.debug(`key is ${apiKey}`);

  // ruleid: node-secret-in-log
  console.error("token: " + session.accessToken);

  // ruleid: node-secret-in-log
  console.log({ user, token });

  // ruleid: node-secret-in-log
  logger.info("session", { id: session.id, auth: session.refreshToken });

  // ruleid: node-secret-in-log
  logger.info("t", { password: pw });

  // ruleid: node-secret-in-log
  logger.info("t", { "api_key": cfg.k });

  // ruleid: node-secret-in-log
  console.log("loaded", JSON.stringify(creds));

  // ok: node-secret-in-log
  console.log("loaded", JSON.stringify(settings));

  // ok: node-secret-in-log
  logger.info("t", { user: name });

  // ok: node-secret-in-log
  console.log({ user, tokenCount });

  // ok: node-secret-in-log
  console.log("signing in", user);

  // ok: node-secret-in-log
  logger.info(`tokens used: ${tokenCount}`);

  // ok: node-secret-in-log
  metrics.log(password);
}
