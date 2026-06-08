"""
LLM 标注 + 人工确认辅助

流程：
  1. 对高频指纹模板，构造提示词让 LLM 猜厂商
  2. 返回厂商名 + 置信度
  3. 人工抽检确认
"""

from typing import List, Optional
from .models import FingerprintTemplate


def build_label_prompt(template: FingerprintTemplate) -> str:
    """构造 LLM 提示词"""
    return f"""You are a fingerprint analyst. Given a protocol banner template, identify the software vendor.

Protocol: {template.protocol}
Standardized template: {template.template}
Sample raw banner: {template.sample_banner}

Rules:
- If the template contains a well-known software name (e.g., "Postfix", "Exim", "OpenSSH"), return that.
- If the template contains a well-known domain suffix (e.g., "google.com", "outlook.com"), return the associated service.
- Otherwise, return "Unknown".
- Output ONLY the vendor name, nothing else.
"""


def parse_llm_label(response: str) -> str:
    """解析 LLM 返回的厂商名"""
    return response.strip().split("\n")[0].strip()


def label_templates(
    templates: List[FingerprintTemplate],
    llm_func=None,
    auto_confirm_threshold: int = 50,
) -> List[FingerprintTemplate]:
    """
    批量标注指纹模板

    参数:
        templates: 指纹模板列表
        llm_func: LLM 调用函数，输入 prompt 返回 response
                  为 None 时跳过 LLM 标注
        auto_confirm_threshold: 高于此数量的模板自动确认标注

    返回:
        标注后的模板列表
    """
    for t in templates:
        if llm_func is not None:
            prompt = build_label_prompt(t)
            response = llm_func(prompt)
            vendor = parse_llm_label(response)
            t.vendor = vendor
        else:
            t.vendor = ""

    return templates
