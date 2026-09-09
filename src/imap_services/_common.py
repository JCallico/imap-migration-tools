"""Private helpers shared by service implementations."""

import logging

from core import imap_session
from imap_services.config import AccountConfig
from imap_services.exceptions import AuthenticationError, ConnectionError
from utils import imap_common

logger = logging.getLogger(__name__)


def build_connection_config(account: AccountConfig, label=None, log_fn=None):
    oauth2 = account.oauth2
    if oauth2 and oauth2.access_token:
        conf = {
            "host": account.host,
            "user": account.username,
            "password": None,
            "oauth2_token": oauth2.access_token,
            "oauth2": {
                "provider": oauth2.provider,
                "client_id": oauth2.client_id,
                "email": account.username,
                "client_secret": oauth2.client_secret,
                "account_type": oauth2.account_type,
            },
        }
        if log_fn is not None:
            conf["log_fn"] = log_fn
        return conf
    try:
        conf = imap_session.build_imap_conf(
            account.host,
            account.username,
            account.password,
            oauth2.client_id if oauth2 else None,
            oauth2.client_secret if oauth2 else None,
            oauth2.account_type if oauth2 else "auto",
            label,
        )
        if log_fn is not None:
            conf["log_fn"] = log_fn
        return conf
    except SystemExit as exc:
        raise AuthenticationError(f"could not authenticate {label or 'account'}") from exc


def connect(account: AccountConfig, label=None, log_fn=None):
    conf = build_connection_config(account, label, log_fn)
    connection = imap_common.get_imap_connection_from_conf(conf)
    if connection is None:
        raise ConnectionError(f"could not connect to {label or 'IMAP account'}")
    return connection, conf
