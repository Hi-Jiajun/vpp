/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __VNET_PPP_PACKET_H__
#define __VNET_PPP_PACKET_H__

/* PPP protocol numbers */
#define PPP_PROTOCOL_IP4 0x0021
#define PPP_PROTOCOL_IP6 0x0057
#define PPP_PROTOCOL_IPX 0x002B
#define PPP_PROTOCOL_VJ_COMP 0x002D
#define PPP_PROTOCOL_VJ_UCOMP 0x002F

/* PPP MPPE */
#define PPP_PROTOCOL_COMP 0x00FD
#define PPP_PROTOCOL_CCP 0x80FD

/* PPP LCP */
#define PPP_PROTOCOL_LCP 0xC021
#define PPP_PROTOCOL_PAP 0xC023
#define PPP_PROTOCOL_CHAP 0xC025

/* PPP NCP */
#define PPP_PROTOCOL_IPCP 0x8021
#define PPP_PROTOCOL_IPV6CP 0x8057

#endif /* __VNET_PPP_PACKET_H__ */
