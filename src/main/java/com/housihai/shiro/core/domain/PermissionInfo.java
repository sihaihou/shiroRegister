package com.housihai.shiro.core.domain;

import org.apache.shiro.authz.annotation.Logical;

import com.housihai.shiro.core.commons.PermissionsRequestCondition;

/**
 * 权限信息
 * @author  reyco
 * @date    2022.11.29
 * @version v1.0.1
 */
public class PermissionInfo {

	private String[] permissions;

	private String[] roles;

	private Logical logical;
	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param other
	 * @return
	 */
	public PermissionInfo combine(PermissionInfo other) {
		String[] permissions = PermissionsRequestCondition.combine(this.permissions, other.permissions);
		String[] roles = PermissionsRequestCondition.combine(this.roles, other.roles);
		Logical logical = PermissionsRequestCondition.combine(this.logical, other.logical);
		return new PermissionInfo(permissions, roles,logical);
	}
	public PermissionInfo() {
	}
	public PermissionInfo(String[] permissions, String[] roles, Logical logical) {
		super();
		this.permissions = permissions;
		this.roles = roles;
		this.logical = logical;
	}

	public String[] getPermissions() {
		return permissions;
	}
	public void setPermissions(String[] permissions) {
		this.permissions = permissions;
	}
	public String[] getRoles() {
		return roles;
	}
	public void setRoles(String[] roles) {
		this.roles = roles;
	}
	public Logical getLogical() {
		return logical;
	}
	public void setLogical(Logical logical) {
		this.logical = logical;
	}
}
