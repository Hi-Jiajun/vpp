# Copyright (c) 2024 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(pppox
  SOURCES
    cli.c
    node.c
    pppox.c
    pppox_api.c
    pppd/sys-vpp.c
    pppd/fsm.c
    pppd/lcp.c
    pppd/ipcp.c
    pppd/upap.c
    pppd/upap.c
    pppd/auth.c
    pppd/chap-md5.c
    pppd/chap-new.c
    pppd/magic.c
    pppd/md5.c
    pppd/utils.c
    pppd/options.c
    pppd/ccp.c
    pppd/ccp.h
    pppd/eap.h
    pppd/ecp.c

  API_FILES
    pppox.api
)
