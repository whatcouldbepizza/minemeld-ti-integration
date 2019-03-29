from __future__ import absolute_import

import logging
import requests
from pyaml import yaml

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)


class Miner(BasePollerFT):
	def configure(self):
		super(Miner, self).configure()

		self.polling_timeout = self.config.get('polling_timeout', 20)
		self.verify_cert = self.config.get('verify_cert', False)
		self.last_file = self.config.get('last_file', "/home/last.yml")
		with open(self.last_file, "r+") as f:
			pass

		self.feeds = self.config.get('feeds', None)
		if self.feeds is None:
			raise ValueError("Feed name is required")

		self.url = self.config.get('url', None)
		if self.url is None:
			raise ValueError("URL is required")

		self.api_username = self.config.get('api_username', None)
		if self.api_username is None:
			raise ValueError("API_USERNAME is required")

		self.api_key = self.config.get('api_key', None)
		if self.api_key is None:
			raise ValueError("API_KEY is required")


	def _process_item(self, item):
		"""
		This function is called on each item returned by _build_iterator function.
		It should return a list if [indicator, value] pairs.
		"""
		result_list = []
		for key, val in item.items():
			value = dict()
			if "ip" in key:
				value["type"] = "IPv4"
			elif "url" in key:
				value["type"] = "URL"
			elif "domain" in key:
				value["type"] = "domain"
			elif "md5" in key:
				value["type"] = "md5"
			elif "sha256" in key:
				value["type"] = "sha256"
			elif "sha1" in key:
				value["type"] = "sha1"
			else:
				value["type"] = "any"
			value["confidence"] = 100
			
			val_listed = val if isinstance(val, list) else [val]

			for elem in val_listed:
				result_list.append([elem, value])

		return result_list


	def get_last(self, feed):
		with open(self.last_file, "r") as f:
			lasts = yaml.load(f)
		return lasts[feed]


	def set_last(self, new, feed):
		with open(self.last_file, "r") as f:
			lasts = yaml.load(f)
		lasts[feed] = new
		with open(self.last_file, "w") as f:
			yaml.dump(lasts, f, default_flow_style=False)


	def _build_iterator(self, now):
		"""
		This function is called at every polling interval.
		Here we should retrieve and return the list of items.
		"""
		feeds = self.feeds.replace(" ", "").split(',')
		total_result = []
		
		for feed in feeds:
			total_result.extend(self.poll_collection(feed))

		return total_result


	def poll_collection(self, feed):
		total_list = []

		headers = {
			"Accept": "application/json",
			"Connection": "Keep-Alive",
			"Keep-Alive": "30",
			"X-Auth-Login": self.api_username,
			"X-Auth-Key": self.api_key
		}

		last = self.get_last(feed)
		limit = 10 if feed == "leaks" else 1000

		while True:
			request_url = "{}?module=get&action={}&limit={}&last={}".format(self.url, feed, limit, last)
			response = requests.get(request_url, headers=headers)

			try:
				response.raise_for_status()
			except:
				LOG.debug("%s - exception during GET to TI: %s %s", self.name, response.status_code, response.content)
				raise

			result = response.json()
			if last == result["data"]["last"]:
				break

			if len(result["data"]["new"]) or len(result["data"]["del"]):
				total_list.extend(self.parse_json(result, feed))

			last = result["data"]["last"]
			self.set_last(last, feed)

		return total_list


	def parse_json(self, json, feed):
		method = getattr(JsonParser(), feed + "_parser")
		parsed_list = []

		for event in json["data"]["new"]:
			try:
				parsed = method(event)
			except Exception:
				LOG.info("Failed to parse event: " + str(event))
				parsed = dict()

			if parsed != dict():
				parsed_list.append(parsed)

		return parsed_list


class JsonParser(object):
	def valid_ip(self, address):
		parts = address.split('.')
		if len(parts) != 4:
			return False
		for part in parts:
			try:
				if not 0 <= int(part) <= 255:
					return False
			except ValueError:
				return False
		return True


	def dict_add_elem(self, key, json, dictionary):
		try:
			if json[key] is not None and len(json[key]):
				dictionary[key] = json[key]
		except KeyError:
			pass

		return dictionary


	def get_block_data(self, keywords, json, dictionary):
		for keyword in keywords:
			for key in [keyword + "_" + x for x in ["ip", "url", "domain"]]:
				dictionary = self.dict_add_elem(key, json, dictionary)

		return dictionary


	def accs_parser(self, event):
		return self.dict_add_elem("login", event["attrs"], self.get_block_data(["cnc"], event["attrs"], dict()))


	def cards_parser(self, event):
		return self.dict_add_elem("card_number", event["attrs"], self.get_block_data(["cnc"], event["attrs"], dict()))


	def imei_parser(self, event):
		to_add = "device_imei" if event["attrs"]["device_imei"] != "~" else ("device_iccid" if event["attrs"]["device_iccid"] != "~" else "device_imsi")
		return self.dict_add_elem(to_add, event["attrs"], self.get_block_data(["cnc"], event["attrs"], dict()))


	def mules_parser(self, event):
		return self.dict_add_elem("account", event["attrs"], self.get_block_data(["cnc"], event["attrs"], dict()))


	def ddos_parser(self, event):
		return self.get_block_data(["cnc", "target"], event["attrs"], dict())


	def domain_parser(self, event):
		return self.dict_add_elem("domain", event["attrs"], self.get_block_data(["server"], event["attrs"], dict()))


	def ssl_parser(self, event):
		result = self.dict_add_elem("domain_name", event["attrs"], self.get_block_data(["server"], event["attrs"], dict()))
		result = self.dict_add_elem("hash", event["attrs"], result)
		if "hash" in result.keys():
			result["hash_sha1"] = result.pop("hash")
		return result


	def phishing_parser(self, event):
		return self.get_block_data(["target", "phishing"], event["attrs"], dict())


	def advert_parser(self, event):
		return self.get_block_data(["advert"], event["attrs"], dict())


	def mobileapp_parser(self, event):
		return self.dict_add_elem("url", event["attrs"], dict())


	def phishingkit_parser(self, event):
		return self.dict_add_elem("phishing_kit", event["attrs"], self.get_block_data(["phishing_kit"], event["attrs"], dict()))


	def tornodes_parser(self, event):
		return self.dict_add_elem("tor_ip", event["attrs"], dict())


	def proxy_parser(self, event):
		return self.dict_add_elem("proxy_ip", event["attrs"], dict())


	def socks_parser(self, event):
		return self.dict_add_elem("socks_ip", event["attrs"], dict())


	def leaks_parser(self, event):
		return self.dict_add_elem("link", event["attrs"], self.dict_add_elem("title", event["attrs"], dict()))


	def threats_parser(self, event):
		result = { "ips": [], "urls": [], "domains": [], "files": [], "md5s": []}
		for ind in event["attrs"]["indicators"]:
			if ind["type"] in ["cnc", "ip", "anonymization"]:
				for val in ind["value"]:
					if self.valid_ip(val):
						result["ips"].append(val)
					else:
						result["urls"].append(val)
			elif ind["type"] in["url", "domain"]:
				result[ind["type"] + "s"].extend(ind["value"])
			elif ind["type"] == "file":
				result["files"].extend(ind["value"])
				if "hash" in ind["params"] and ind["params"]["hash"]:
					result["md5s"].append(ind["params"]["hash"])
			elif ind["type"] == "file_hash":
				result["md5s"].extend(ind["value"])
		return result
