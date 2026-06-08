"""
Banner 标准化器（论文 Algorithm 3-1 的 Python 实现）

标准化流程：
  1. 域名字段替换
  2. 时间字段替换
  3. 随机标识替换

每协议一套规则，通过 YAML 配置驱动。
"""

import re
import yaml
from pathlib import Path
from typing import Optional
from .models import StandardizedBanner


class Standardizer:
    def __init__(self, config_path: Optional[str] = None):
        self.rules: dict = {}
        if config_path:
            self.load_config(config_path)

    def load_config(self, config_path: str):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        self.rules[cfg["protocol"]] = cfg["normalize"]

    def normalize(self, banner: StandardizedBanner) -> StandardizedBanner:
        """执行完整标准化流水线"""
        proto = banner.protocol
        rules = self.rules.get(proto, {})
        text = banner.original

        # 1. 域名字段标准化
        domain_rules = rules.get("domain", {})
        if domain_rules.get("enabled", True):
            text = self._normalize_domain(text, domain_rules, banner)

        # 2. 时间字段标准化
        time_rules = rules.get("timestamp", {})
        if time_rules.get("enabled", True):
            text = self._normalize_timestamp(text, time_rules)

        # 3. 随机标识标准化
        random_rules = rules.get("random_id", {})
        if random_rules.get("enabled", True):
            text = self._normalize_random_id(text, random_rules)

        banner.standardized = text
        return banner

    def _normalize_domain(self, text: str, rules: dict, banner: StandardizedBanner) -> str:
        known = rules.get("known_suffixes", [])
        replacement = rules.get("unknown_replacement", "[DomainName]")
        pattern = r'[\w.-]+\.(?:' + '|'.join(re.escape(s) for s in known) + ')'

        def replace_domain(m: re.Match) -> str:
            full = m.group(0)
            for suffix in known:
                if full.endswith(suffix):
                    banner.domain_family = suffix
                    return suffix
            return replacement

        return re.sub(pattern, replace_domain, text)

    def _normalize_timestamp(self, text: str, rules: dict) -> str:
        for pattern_str in rules.get("patterns", []):
            text = re.sub(pattern_str, rules.get("replacement", "[DateTime]"), text)
        return text

    def _normalize_random_id(self, text: str, rules: dict) -> str:
        for pattern_str in rules.get("patterns", []):
            text = re.sub(pattern_str, rules.get("replacement", "[RandomID]"), text)
        return text

    def register_protocol(self, protocol: str, rules: dict):
        """动态注册新协议的标准化规则"""
        self.rules[protocol] = rules


# ==== SMTP 默认规则 ====
SMTP_RULES = {
    "protocol": "SMTP",
    "normalize": {
        "domain": {
            "enabled": True,
            "known_suffixes": [
                "google.com", "outlook.com", "qq.com", "163.com",
                "yahoo.com", "icloud.com", "protonmail.com",
                "barracuda.com", "pphosted.com", "mimecast.com",
            ],
            "unknown_replacement": "[DomainName]",
        },
        "timestamp": {
            "enabled": True,
            "patterns": [
                r'\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} [+\-]\d{4}',
                r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            ],
            "replacement": "[DateTime]",
        },
        "random_id": {
            "enabled": True,
            "patterns": [
                r'[a-f0-9]{8,}',
                r'[A-Za-z0-9+/]{20,}',
            ],
            "replacement": "[RandomID]",
        },
    },
}

# ==== SSH 默认规则 ====
SSH_RULES = {
    "protocol": "SSH",
    "normalize": {
        "domain": {
            "enabled": False,
        },
        "timestamp": {
            "enabled": False,
        },
        "random_id": {
            "enabled": True,
            "patterns": [
                r'_[a-f0-9]{7,}',
            ],
            "replacement": "",
        },
    },
}

# ==== HTTP 默认规则 ====
HTTP_RULES = {
    "protocol": "HTTP",
    "normalize": {
        "domain": {
            "enabled": False,
        },
        "timestamp": {
            "enabled": True,
            "patterns": [
                r'Date: \w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT',
            ],
            "replacement": "Date: [DateTime] GMT",
        },
        "random_id": {
            "enabled": False,
        },
    },
}
