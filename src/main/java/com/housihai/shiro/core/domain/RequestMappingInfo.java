package com.housihai.shiro.core.domain;

import org.springframework.web.bind.annotation.RequestMethod;
/**
 * @author  reyco
 * @date    2022.11.28
 * @version v1.0.1
 */

import com.housihai.shiro.core.commons.ConsumesRequestCondition;
import com.housihai.shiro.core.commons.HeadersRequestCondition;
import com.housihai.shiro.core.commons.MethodRequestCondition;
import com.housihai.shiro.core.commons.ParamsRequestCondition;
import com.housihai.shiro.core.commons.PatternsRequestCondition;
import com.housihai.shiro.core.commons.ProducesRequestCondition;

/**
 * 请求映射信息
 * @author  reyco
 * @date    2022.11.25
 * @version v1.0.1
 */
public class RequestMappingInfo {
	/**
	 * 请求路径
	 */
	private String[] paths;
	/**
	 * 请求方式
	 */
	private String[] methods;
	/**
	 * 指定request中必须包含某些参数值是，才让该方法处理。
	 */
	private String[] params;
	/**
	 * 指定request中必须包含某些指定的header值，才能让该方法处理请求。
	 */
	private String[] headers;
	/**
	 * 指定处理请求的提交内容类型（Content-Type），例如application/json, text/html;
	 */
	private String[] consumes;
	/**
	 *  指定返回的内容类型，仅当request请求头中的(Accept)类型中包含该指定类型才返回
	 */
	private String[] produces;
	/**
	 * 权限
	 */
	private PermissionInfo permissionInfo;
	/**
	 *
	 */
	public RequestMappingInfo() {
		// TODO Auto-generated constructor stub
	}

	public RequestMappingInfo(String[] paths,String[] methods,  String[] params, String[] headers, String[] consumes,
			String[] produces) {
		super();
		this.paths = paths;
		this.methods = methods;
		this.params = params;
		this.headers = headers;
		this.consumes = consumes;
		this.produces = produces;
	}
	private RequestMappingInfo(Builder builder) {
		this.methods = builder.methods;
		this.paths = builder.paths;
		this.params = builder.params;
		this.headers = builder.headers;
		this.consumes = builder.consumes;
		this.produces = builder.consumes;
		this.permissionInfo = builder.permissionInfo;
	}
	public String[] getMethods() {
		return methods;
	}
	public void setMethods(String[] methods) {
		this.methods = methods;
	}
	public String[] getPaths() {
		return paths;
	}
	public void setPaths(String[] paths) {
		this.paths = paths;
	}
	public String[] getParams() {
		return params;
	}
	public void setParams(String[] params) {
		this.params = params;
	}
	public String[] getHeaders() {
		return headers;
	}
	public void setHeaders(String[] headers) {
		this.headers = headers;
	}
	public String[] getConsumes() {
		return consumes;
	}
	public void setConsumes(String[] consumes) {
		this.consumes = consumes;
	}
	public String[] getProduces() {
		return produces;
	}
	public void setProduces(String[] produces) {
		this.produces = produces;
	}
	public PermissionInfo getPermissionInfo() {
		return permissionInfo;
	}
	public void setPermissionInfo(PermissionInfo permissionInfo) {
		this.permissionInfo = permissionInfo;
	}
	public RequestMappingInfo combine(RequestMappingInfo other) {
		String[] paths = PatternsRequestCondition.combine(this.paths, other.paths);
		String[] methods = MethodRequestCondition.combine(this.methods,other.methods);
		String[] params = ParamsRequestCondition.combine(this.params,other.params);
		String[] headers = HeadersRequestCondition.combine(this.headers,other.headers);
		String[] consumes = ConsumesRequestCondition.combine(this.consumes,other.consumes);
		String[] produces = ProducesRequestCondition.combine(this.produces,other.produces);
		return new RequestMappingInfo(paths,methods, params, headers, consumes,produces);
	}
	@SuppressWarnings("all")
	public static class Builder{
		private String[] paths;
		private String[] methods;
		private String[] params;
		private String[] headers;
		private String[] consumes;
		private String[] produces;
		private PermissionInfo permissionInfo;
		public Builder() {
		}
		public Builder buildPaths(String[] paths){
			this.paths = paths;
			return this;
		}
		public Builder buildMethods(String[] methods){
			this.methods = methods;
			return this;
		}
		public Builder buildMethods(RequestMethod[] methods){
			String[] tempMethods = new String[methods.length];
			for(int i=0;i<methods.length;i++) {
				tempMethods[i] = methods[i].name();
			}
			this.methods = tempMethods;
			return this;
		}
		public Builder buildParams(String[] params){
			this.params = params;
			return this;
		}
		public Builder buildHeaders(String[] headers){
			this.headers = headers;
			return this;
		}
		public Builder buildConsumes(String[] consumes){
			this.consumes = consumes;
			return this;
		}
		public Builder buildProduces(String[] produces){
			this.produces = produces;
			return this;
		}
		public Builder buildPermissionInfo(PermissionInfo permissionInfo){
			this.permissionInfo = permissionInfo;
			return this;
		}
		public RequestMappingInfo build() {
			return new RequestMappingInfo(this);
		}
	}
}
