import jwt


def check(token, key, user, resource):
    # ruleid: python-broad-except-swallows-security-check
    try:
        claims = jwt.decode(token, key, algorithms=["RS256"])
    except Exception:
        pass

    # ruleid: python-broad-except-swallows-security-check
    try:
        verify_signature(payload, signature)
    except:
        pass

    for item in items:
        # ruleid: python-broad-except-swallows-security-check
        try:
            authorize(user, item)
        except BaseException as exc:
            continue

    # ruleid: python-broad-except-swallows-security-check
    try:
        log.info("checking")
        allowed = policy.is_authorized(user, resource)
    except Exception as e:
        logger.warning("authz failed: %s", e)

    # ok: python-broad-except-swallows-security-check
    try:
        claims = jwt.decode(token, key, algorithms=["RS256"])
    except jwt.InvalidTokenError:
        raise PermissionError("invalid token")

    # ok: python-broad-except-swallows-security-check
    try:
        verify_signature(payload, signature)
    except Exception:
        return False

    # ok: python-broad-except-swallows-security-check
    try:
        render(page)
    except Exception:
        pass

    # ok: python-broad-except-swallows-security-check
    try:
        return verifier.verify(header)
    except Exception as exc:
        log("auth_refused", error=type(exc).__name__)
        context.abort(UNAUTHENTICATED, "invalid token")

    # ruleid: python-broad-except-swallows-security-check
    try:
        decision = await client.authorize(principal, action, resource)
    except Exception:
        logger.exception("authorization call failed")

    # ok: python-broad-except-swallows-security-check
    try:
        install_proxy(url, token)
    except Exception as err:
        raise Unavailable("could not install") from err

    # ok: python-broad-except-swallows-security-check
    try:
        headers = {"Proxy-Authorization": egress.proxy_authorization()}
        await client.close_session(run)
    except Exception:
        logger.warning("best-effort close failed")

    # ok: python-broad-except-swallows-security-check
    try:
        text = payload.decode("utf-8")
    except Exception:
        pass
