"""
贪心阈值聚类（论文 Algorithm 3-2 的 Python 实现）

流程：
  1. 对标准化后的 banner 计算两两综合相似度
  2. 从第一个未分配样本开始，相似度 ≥ 阈值的归入同一簇
  3. 重复直到全部分配完毕

综合相似度 = 0.7 × SequenceMatcher + 0.3 × TF-IDF 余弦相似度
"""

from difflib import SequenceMatcher
from typing import List
from sklearn.feature_extraction.text import TfidfVectorizer
from .models import StandardizedBanner, FingerprintTemplate
from collections import Counter
import re


def seq_sim(a: str, b: str) -> float:
    """字符级序列相似度（论文公式 3-1）"""
    return SequenceMatcher(None, a, b).ratio()


def compute_similarities(texts: List[str]) -> dict:
    """批量计算所有文本对的综合相似度矩阵"""
    n = len(texts)
    if n == 0:
        return {}

    # TF-IDF 向量化
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 2))
    try:
        tfidf_matrix = vectorizer.fit_transform(texts)
    except ValueError:
        tfidf_matrix = None

    sims = {}
    for i in range(n):
        for j in range(i + 1, n):
            # 字符级序列相似度
            char_sim = seq_sim(texts[i], texts[j])

            # TF-IDF 余弦相似度
            cos_sim = 0.0
            if tfidf_matrix is not None:
                vi = tfidf_matrix[i].toarray().flatten()
                vj = tfidf_matrix[j].toarray().flatten()
                norm = (sum(vi**2) ** 0.5) * (sum(vj**2) ** 0.5)
                if norm > 0:
                    cos_sim = sum(vi * vj) / norm

            # 加权融合（论文公式 3-4）
            combined = 0.7 * char_sim + 0.3 * cos_sim
            sims[(i, j)] = combined

    return sims


def cluster_greedy(
    banners: List[StandardizedBanner],
    threshold: float = 0.7,
) -> List[List[StandardizedBanner]]:
    """
    贪心阈值聚类（论文 Algorithm 3-2）

    参数:
        banners: 标准化后的 banner 列表
        threshold: 相似度阈值 θ，默认 0.7

    返回:
        簇列表，每个簇是一个 banner 列表
    """
    texts = [b.standardized for b in banners]
    n = len(texts)
    assigned = [False] * n
    clusters: List[List[StandardizedBanner]] = []

    # 预计算相似度
    sims = compute_similarities(texts)

    for i in range(n):
        if assigned[i]:
            continue

        # 新簇
        cluster = [banners[i]]
        assigned[i] = True

        # 扫描剩余未分配样本
        for j in range(i + 1, n):
            if assigned[j]:
                continue

            sim = sims.get((i, j), 0.0)
            if sim >= threshold:
                cluster.append(banners[j])
                assigned[j] = True

        clusters.append(cluster)

    return clusters


def clusters_to_templates(clusters: List[List[StandardizedBanner]]) -> List[FingerprintTemplate]:
    """将聚类结果转为指纹模板列表"""
    templates = []
    for cluster in clusters:
        if not cluster:
            continue

        # 取簇中最短的标准化文本作为模板
        cluster.sort(key=lambda b: len(b.standardized))
        template_text = cluster[0].standardized

        # 生成正则模式：转义正则特殊字符，保留 [DomainName] 等占位符
        pattern = re.escape(template_text)
        # 将占位符恢复为通配模式
        for placeholder in ["[DomainName]", "[DateTime]", "[RandomID]"]:
            pattern = pattern.replace(re.escape(placeholder), r".+?")

        # 取频次最高的原始 banner 作为样本
        raw_banners = [b.original for b in cluster]
        sample = Counter(raw_banners).most_common(1)[0][0]

        templates.append(FingerprintTemplate(
            protocol=cluster[0].protocol,
            template=template_text,
            pattern=pattern,
            count=len(cluster),
            sample_banner=sample,
        ))

    # 按频次降序
    templates.sort(key=lambda t: t.count, reverse=True)
    return templates
