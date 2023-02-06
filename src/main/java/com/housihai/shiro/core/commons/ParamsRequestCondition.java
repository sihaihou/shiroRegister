package com.housihai.shiro.core.commons;

/**
 * 请求的参数值合并
 * @author  reyco
 * @date    2022.11.28
 * @version v1.0.1
 */
public class ParamsRequestCondition {

	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param params
	 * @param other
	 * @return
	 */
	public static String[] combine(String[] params,String[] other) {
		String[] result = new String[params.length+other.length];
		int index = 0;
		for (int i = 0; i < params.length; i++) {
			result[index++] = params[i];
		}
		for (int i = 0; i < other.length; i++) {
			result[index++] = other[i];
		}
		return result;
	}
}
