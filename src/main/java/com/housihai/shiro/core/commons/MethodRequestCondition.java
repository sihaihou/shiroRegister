package com.housihai.shiro.core.commons;

/**
 * 支持请求方法类型合并
 * @author  reyco
 * @date    2022.11.28
 * @version v1.0.1
 */
public class MethodRequestCondition {
	/**
	 * 方法上的标记和类上的标记合并
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param methods
	 * @param other
	 * @return
	 */
	public static String[] combine(String[] methods,String[] other) {
		String[] result = new String[methods.length+other.length];
		int index = 0;
		for (int i = 0; i < methods.length; i++) {
			result[index++] = methods[i];
		}
		for (int i = 0; i < other.length; i++) {
			result[index++] = other[i];
		}
		return result;
	}

}
