# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style bitflip mutations (deterministic stage).

Disabled in current configuration.
"""

def mutate_seq_walking_bits(data, func, skip_null=False, effector_map=None):
    return


def mutate_seq_two_walking_bits(data, func, skip_null=False, effector_map=None):
    return


def mutate_seq_four_walking_bits(data, func, skip_null=False, effector_map=None):
    return


def mutate_seq_walking_byte(data, func, effector_map=None, limiter_map=None, skip_null=False):
    return


def mutate_seq_two_walking_bytes(data, func, effector_map=None, skip_null=False):
    return


def mutate_seq_four_walking_bytes(data, func, effector_map=None, skip_null=False):
    return
