"""
新 banner 匹配已有指纹库

流程：
  1. 对新 banner 做标准化
  2. 与指纹库中每个模板计算综合相似度
  3. 取相似度最高的模板（超过阈值）作为匹配结果
"""

from typing import List
from .models import StandardizedBanner, FingerprintTemplate
from .cluster import seq_sim


def match(
    banner: StandardizedBanner,
    templates: List[FingerprintTemplate],
    threshold: float = 0.7,
) -> tuple[Optional[FingerprintTemplate], float]:
    """
    匹配 banner 到指纹库

    返回:
        (匹配的模板, 相似度)
        若无匹配则返回 (None, 0.0)
    """
    if not banner.standardized:
        return None, 0.0

    best_template = None
    best_score = 0.0

    for t in templates:
        score = seq_sim(banner.standardized, t.template)
        if score > best_score and score >= threshold:
            best_score = score
            best_template = t

    return best_template, best_score
