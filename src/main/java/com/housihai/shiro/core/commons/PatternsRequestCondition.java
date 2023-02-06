package com.housihai.shiro.core.commons;

import org.springframework.util.AntPathMatcher;

/**
 * 请求路径拼接规则
 * @author reyco
 * @date 2022.11.28
 * @version v1.0.1
 */
public class PatternsRequestCondition {

	private static AntPathMatcher pathMatcher = new AntPathMatcher();
	/**
	 * @author  reyco
	 * @date    2022年11月28日
	 * @version v1.0.1
	 * @param patterns
	 * @param other
	 * @return
	 */
	public static String[] combine(String[] patterns,String[] other) {
		if (patterns!=null && patterns.length!=0 && other!=null && other.length!=0) {
			String[] result = new String[patterns.length*other.length];
			int index = 0;
			for (String pattern1 : patterns) {
				for (String pattern2 : other) {
					result[index] = pathMatcher.combine(pattern1, pattern2);
				}
			}
			return result;
		}else if (patterns!=null && patterns.length!=0) {
			return patterns;
		}else if (other!=null && other.length!=0) {
			return other;
		}else {
			return new String[] {""};
		}
	}
}
