"""Tests for aioruckus."""
from os import environ

from aioruckus import AjaxSession

HOST = environ.get("RUCKUS_HOST", "192.168.0.1")
USERNAME = environ.get("RUCKUS_USERNAME", "super")
PASSWORD = environ.get("RUCKUS_PASSWORD", "sp-admin")


def connect_ruckus(host=HOST, username=USERNAME, password=PASSWORD):
    return AjaxSession.async_create(host, username, password)
