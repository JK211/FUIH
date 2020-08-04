#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class gol(object):
    global _global_dict

    def __init__(self):
        self._global_dict = {}

    def set_value(self, key, value):
        self._global_dict[key] = value

    def get_value(self, key, defValue=None):
        try:
            return self._global_dict[key]
        except KeyError:
            return defValue

