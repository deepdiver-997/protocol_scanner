"""
K-Medoids 聚类（论文 3.2.3 节 Webmail 同源性分析）

与贪心聚类的区别：
- 贪心聚类：阈值驱动，簇数自动确定，适合 Banner 文本
- K-Medoids：指定 K，迭代优化簇中心，适合 DOM 序列

算法:
  1. 随机选择 K 个初始 medoids
  2. 分配每个点到最近的 medoid
  3. 对每个簇，找到总距离最小的点作为新 medoid
  4. 重复 2-3 直到收敛
"""

import random
from typing import List, Tuple, Optional
from fingerprint.models import FingerprintTemplate


def levenshtein_distance(a: str, b: str) -> int:
    """编辑距离（用于 DOM 标签序列比较）"""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,        # 删除
                prev[j + 1] + 1,    # 插入
                prev[j] + cost,     # 替换
            ))
        prev = curr
    return prev[-1]


def _build_distance_matrix(texts: List[str]) -> List[List[float]]:
    n = len(texts)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            d = float(levenshtein_distance(texts[i], texts[j]))
            matrix[i][j] = d
            matrix[j][i] = d
    return matrix


def _total_distance(medoid_idx: int, member_indices: List[int], dist_matrix: List[List[float]]) -> float:
    """medoid 到簇内所有点的总距离"""
    return sum(dist_matrix[medoid_idx][m] for m in member_indices)


def kmedoids_auto(
    texts: List[str],
    k: int,
    n_restarts: int = 20,
    max_iter: int = 100,
) -> Tuple[List[List[int]], List[int], float]:
    """
    自动多轮重启的 K-Medoids

    跑 n_restarts 次，选总势能最小的结果。

    返回:
        (best_clusters, best_medoids, best_potential)
    """
    best = None
    best_potential = float("inf")

    for seed in range(n_restarts):
        clusters, medoids = kmedoids(texts, k, max_iter, random_seed=seed)
        # 计算总势能
        dist_matrix = _build_distance_matrix(texts)
        potential = 0.0
        for m, med in enumerate(medoids):
            for idx in clusters[m]:
                potential += dist_matrix[med][idx]
        if potential < best_potential:
            best_potential = potential
            best = (clusters, medoids)

    return best[0], best[1], best_potential


def kmedoids(
    texts: List[str],
    k: int,
    max_iter: int = 100,
    random_seed: Optional[int] = None,
) -> Tuple[List[List[int]], List[int]]:
    """
    K-Medoids 聚类

    参数:
        texts: 输入序列列表
        k: 簇数量
        max_iter: 最大迭代次数
        random_seed: 随机种子

    返回:
        (clusters, medoids)
        clusters[m] = [点索引列表]
        medoids[m] = medoid 的索引
    """
    n = len(texts)
    if k <= 0 or k > n:
        raise ValueError(f"K must be between 1 and {n}")

    if random_seed is not None:
        random.seed(random_seed)

    # 预计算距离矩阵
    dist_matrix = _build_distance_matrix(texts)

    # 1. 初始化：随机选 K 个 medoids
    medoids = random.sample(range(n), k)
    prev_medoids = []

    for iteration in range(max_iter):
        # 2. 分配：每个点归到最近的 medoid
        clusters: List[List[int]] = [[] for _ in range(k)]
        for i in range(n):
            nearest = min(range(k), key=lambda m: dist_matrix[i][medoids[m]])
            clusters[nearest].append(i)

        # 3. 更新：对每个簇找新的 medoid
        new_medoids = []
        for m in range(k):
            if not clusters[m]:
                new_medoids.append(medoids[m])
                continue
            best = min(
                clusters[m],
                key=lambda idx: _total_distance(idx, clusters[m], dist_matrix),
            )
            new_medoids.append(best)

        # 检查收敛
        if new_medoids == medoids or new_medoids == prev_medoids:
            break

        prev_medoids = medoids
        medoids = new_medoids

    # 最终分配
    clusters = [[] for _ in range(k)]
    for i in range(n):
        nearest = min(range(k), key=lambda m: dist_matrix[i][medoids[m]])
        clusters[nearest].append(i)

    return clusters, medoids


def elbow_k(texts: List[str], max_k: int = 20) -> Tuple[int, List[float]]:
    """
    Elbow 法确定最佳 K

    计算 K=1..max_k 的 WCSS（簇内平方和），
    返回推荐 K 和 WCSS 列表（用于画图）

    用法:
        k, wcss = elbow_k(texts, max_k=20)
        # 手动选肘部位置
    """
    wcss_list = []
    for k in range(1, max_k + 1):
        clusters, medoids = kmedoids(texts, k, random_seed=42)
        wcss = 0.0
        dist_matrix = _build_distance_matrix(texts)
        for m, med in enumerate(medoids):
            for idx in clusters[m]:
                wcss += dist_matrix[med][idx] ** 2
        wcss_list.append(wcss)

    # 自动建议：找下降率最大的拐点
    if len(wcss_list) < 3:
        return 1, wcss_list

    # 计算二阶导数的近似值
    diffs = [wcss_list[i] - wcss_list[i + 1] for i in range(len(wcss_list) - 1)]
    # 找下降率骤降的位置
    if len(diffs) < 2:
        recommended = 1
    else:
        # 找下降率变化最大的点
        rate_changes = [diffs[i] - diffs[i + 1] for i in range(len(diffs) - 1)]
        recommended = rate_changes.index(max(rate_changes)) + 2  # +2 因为偏移

    return min(recommended, max_k), wcss_list


def kmedoids_to_templates(
    clusters: List[List[int]],
    medoids: List[int],
    texts: List[str],
    protocol: str = "WEBMAIL",
) -> List[FingerprintTemplate]:
    """将 K-Medoids 聚类结果转为指纹模板"""
    templates = []
    for m, med in enumerate(medoids):
        members = clusters[m]
        if not members:
            continue
        templates.append(FingerprintTemplate(
            protocol=protocol,
            template=texts[med],
            pattern="",
            vendor="",
            count=len(members),
            sample_banner=texts[members[0]],
        ))
    templates.sort(key=lambda t: t.count, reverse=True)
    return templates
