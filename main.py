#! /usr/bin/env python

from __future__ import print_function
from scipy.stats import entropy
from scapy.all import *
import numpy as np
import dpkt
import logging
logging.basicConfig(filename="log.txt", level=logging.DEBUG)


def conn(ip1, ip2, port1, port2):
	swap = False

	if ip1 > ip2:
		ip1, ip2 = ip2, ip1
		port1, port2 = port2, port1
		swap = True

	if ip1 == ip2 and port1 > port2:
		port1, port2 = port2, port1
		swap = True

	return (ip1, ip2, port1, port2), swap

def dist(str):
	p = np.zeros(256)
	for i in str:
		p[ord(i)] += 1
	return p

score = {}
blocked = {}
thres = 16
sample = 128
limit = sample * 128
mtu = 1600
logging.debug(datetime.now())
def add_score(c, x):
	if c in blocked:
		return
	if c not in score:
		score[c] = x
	else:
		score[c] += x
	if score[c] >= thres:
		logging.debug("detected:", c)
		blocked[c] = True
	print(type(c))
	logging.debug('[', datetime.now(), ']', c, score[c])

def add(c, x):
	add_score((c[0], c[2]), x)
	add_score((c[1], c[3]), x)

track = {}
def sniffer(pkt):
	ip = pkt.payload
	tcp = ip.payload
	c, s = conn(ip.src, ip.dst, tcp.sport, tcp.dport)

	if tcp.flags & dpkt.tcp.TH_SYN != 0:
		track[c] = []
	if c not in track:
		return

	if tcp.flags & dpkt.tcp.TH_FIN != 0 or tcp.flags & dpkt.tcp.TH_RST != 0:
		del track[c]
		return

		# SS Original
	if tcp.flags & dpkt.tcp.TH_PUSH != 0:
		track[c].append((entropy(dist(str(tcp.payload))), s))
		if len(track[c]) >= 4:
			if track[c][0][0] > 4.8 or \
				(track[c][0][0] > 4.4 and track[c][1][0] > 4.2) or \
				(track[c][0][0] > 4.2 and track[c][2][0] > 4.2 and \
				track[c][0][1] == track[c][2][1]) or \
				track[c][0][1] == track[c][1][1]:
					add(c, 1)
			else:
					add(c, -1)
			del track[c]


len_dist = {}
len_count = {}
def ssr_sniffer(pkt):
	ip = pkt.payload
	tcp = ip.payload
	c = (ip.src, tcp.sport)

	if c not in len_count:
		len_count[c] = 0
		len_dist[c] = np.zeros(mtu)

		# SSR
	if tcp.flags & dpkt.tcp.TH_PUSH != 0:
		l = len(tcp.payload) % mtu
		len_dist[c][l] += 1

		if len_count[c] > 0 and len_count[c] % sample == 0:
			e = entropy(len_dist[c])
			len_dist[c] = np.zeros(mtu)
			# print(len_count)
			# print(len_dist[c])
			# print(c, e)
			if e > 4.0:
				add_score(c, 2)
			elif e > 3.4:
				add_score(c, 1)
			elif e < 3.0:
				add_score(c, -1)
			elif e < 2.5:
				add_score(c, -2)

		len_count[c] += 1

		if len_count[c] > limit:
			del len_count[c]
			del len_dist[c]
			del score[c]


sniff(filter='tcp', store=False, prn=ssr_sniffer)
