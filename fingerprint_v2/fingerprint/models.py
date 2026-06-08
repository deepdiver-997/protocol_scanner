# 数据模型
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BannerRecord:
    """单次探测结果，对应 C++ --format fingerprint 的一行 JSONL"""
    seq: int
    ip: str
    port: int
    protocol: str       # "SMTP", "SSH", "HTTP", "FTP", ...
    banner: str         # 原始 banner 文本
    time: int           # unix timestamp

    @classmethod
    def from_json(cls, d: dict) -> "BannerRecord":
        return cls(
            seq=d["seq"],
            ip=d["ip"],
            port=d["port"],
            protocol=d["protocol"].upper(),
            banner=d.get("banner", ""),
            time=d.get("time", 0),
        )


@dataclass
class FingerprintTemplate:
    """聚类产出的指纹模板"""
    protocol: str
    template: str               # 标准化后的模板文本
    pattern: str                # 对应的正则匹配模式（用于 vendors.json）
    vendor: str = ""            # 厂商名，LLM 标注后填入
    count: int = 0              # 匹配样本数
    sample_banner: str = ""     # 一条原始样本（供人工/LLM 参考）


@dataclass
class StandardizedBanner:
    """标准化后的 banner"""
    protocol: str
    original: str
    standardized: str = ""
    domain_family: str = ""     # 提取的域名族，如 "google.com"
