import logging

logger = logging.getLogger(__name__)


def login(user, password, api_key, session):
    # ruleid: python-secret-in-log
    logger.info("login for %s with %s", user, password)

    # ruleid: python-secret-in-log
    logging.debug(f"using key {api_key}")

    # ruleid: python-secret-in-log
    logger.error("token: %s" % session.access_token)

    # ruleid: python-secret-in-log
    self.log.warning("refresh {}".format(refresh_token))

    # ruleid: python-secret-in-log
    logger.info("signed in", extra={"user": user, "token": session_token})

    # ruleid: python-secret-in-log
    logger.debug("signing with %s", app.secret_key)

    # ruleid: python-secret-in-log
    print(token)

    # ruleid: python-secret-in-log
    print(f"key={api_key}")

    # ruleid: python-secret-in-log
    logger.info("login", extra={"user": user, "password": form.value})

    # ruleid: python-secret-in-log
    logging.getLogger(__name__).info("refresh %s", token)

    # ruleid: python-secret-in-log
    log.info("issued", token=token)

    # ruleid: python-secret-in-log
    log.info("issued", api_key=current.key)

    # ruleid: python-secret-in-log
    logger.debug("loaded %s", creds)

    # ok: python-secret-in-log
    log.info("issued", user=user, count=3)

    # ok: python-secret-in-log
    logger.info("login", extra={"user": user, "attempts": 3})

    # ok: python-secret-in-log
    print("token refreshed")

    # ok: python-secret-in-log
    logger.info("login for %s", user)

    # ok: python-secret-in-log
    logger.info("token count %d", token_count)

    # ok: python-secret-in-log
    logger.info("password changed for %s", user.id)

    # ok: python-secret-in-log
    metrics.info(password)
