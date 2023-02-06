package com.housihai.shiro.core.commons;

/**
 * 请求的内容类型Content-Type拼接规则
 * @author  reyco
 * @date    2022.11.28
 * @version v1.0.1
 */
public class ConsumesRequestCondition {

	public static String[] combine(String[] consumes,String[] other) {
		return (other!=null && other.length!=0) ? other : consumes;
	}
}
