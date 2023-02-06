package com.housihai.shiro.core.commons;

/**
 * 返回类型类型合并规则
 * @author  reyco
 * @date    2022.11.28
 * @version v1.0.1
 */
public class ProducesRequestCondition {

	/**
	 * 如果方法有则以方法上的为准
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param produces
	 * @param other
	 * @return
	 */
	public static String[] combine(String[] produces,String[] other) {
		return (other!=null && other.length!=0) ? other : produces;
	}
}
