package com.housihai.shiro.core.commons;

import org.apache.shiro.authz.annotation.Logical;

/**
 * @author  reyco
 * @date    2022.11.29
 * @version v1.0.1
 * 权限拼接
 */
public class PermissionsRequestCondition {

	/**
	 * 将类上的权限和方法上的权限进行合并
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param permissions
	 * @param other
	 * @return
	 */
	public static String[] combine(String[] permissions,String[] other) {
		if(permissions==null && other==null) {
			return null;
		}
		if(permissions==null) {
			String[] result = new String[other.length];
			int index = 0;
			for (int i = 0; i < other.length; i++) {
				result[index++] = other[i];
			}
			return result;
		}
		if(other==null) {
			String[] result = new String[permissions.length];
			int index = 0;
			for (int i = 0; i < permissions.length; i++) {
				result[index++] = permissions[i];
			}
			return result;
		}
		String[] result = new String[permissions.length+other.length];
		int index = 0;
		for (int i = 0; i < permissions.length; i++) {
			result[index++] = permissions[i];
		}
		for (int i = 0; i < other.length; i++) {
			result[index++] = other[i];
		}
		return result;
	}
	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param logical
	 * @param other
	 * @return
	 */
	public static Logical combine(Logical logical,Logical other) {
		return other!=null ? other : logical;
	}
}
