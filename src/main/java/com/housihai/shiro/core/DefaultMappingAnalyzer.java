package com.housihai.shiro.core;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.*;

import com.housihai.shiro.core.domain.PermissionInfo;
import com.housihai.shiro.core.domain.RequestMappingInfo;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;

/**
 * 请求路径解析器
 * @author  reyco
 * @date    2022.11.25
 * @version v1.0.1
 */
public class DefaultMappingAnalyzer implements MappingAnalyzer {
	// 方法请求类型
	public static final Class<?>[] MAPPPING_TYPES = {RequestMapping.class,GetMapping.class,PostMapping.class,
													DeleteMapping.class,PutMapping.class,PatchMapping.class};
	// shiro注解
	public static final Class<?>[] PERMISSSION_TYPES = {RequiresPermissions.class,RequiresRoles.class};

	/**
	 * 构建RequestMappingInfo对象
	 * @param AnnotatedElement 方法
	 * @param handlerType 类对象
	 */
	@Override
	public RequestMappingInfo analyzerRequestMappingInfo(AnnotatedElement element,Class<?> handlerType) {
		RequestMappingInfo requestMappingInfo = null;
		// 解析请求注解，构建请求RequestMappingInfo
		if((requestMappingInfo=createRequestMappingInfo(element, handlerType))==null) {
			return requestMappingInfo;
		}
		// 解析权限注解，构建请求RequestMappingInfo
		PermissionInfo permissionInfo = createPermission(element, handlerType);
		requestMappingInfo.setPermissionInfo(permissionInfo);
		return requestMappingInfo;
	}
	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param method
	 * @param handlerType
	 * @return
	 * 构建RequestMappingInfo
	 */
	private RequestMappingInfo createRequestMappingInfo(AnnotatedElement element,Class<?> handlerType) {
		RequestMappingInfo requestMappingInfo = null;
		// 非公开Mapping方法或者没有权限标识方法直接返回
		// 或者方法上请求映射信息为空也直接返回
		if(!isMapping(element) || !isPermission(element) || (requestMappingInfo = doCeateRequestMappingInfo(element))==null) {
			return requestMappingInfo;
		}
		// 通过类上的请求信息构建RequestMappingInfo
		RequestMappingInfo typeInfo = doCeateRequestMappingInfo(handlerType);
		// 类上的请求信息与方法上的进行合并
		requestMappingInfo = typeInfo.combine(requestMappingInfo);
		return requestMappingInfo;
	}
	/**
	 * 解析shiro注解
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param method
	 * @param handlerType
	 * @return
	 */
	private PermissionInfo createPermission(AnnotatedElement element,Class<?> handlerType) {
		PermissionInfo permissionInfo = doCreatePermissionInfo(element);
		PermissionInfo typeInfo = doCreatePermissionInfo(handlerType);
		if(typeInfo!=null) {
			typeInfo.combine(permissionInfo);
		}
		return permissionInfo;
	}
	/**
	 * 创建RequestMappingInfo
	 * @author  reyco
	 * @date    2022年11月29日
	 * @version v1.0.1
	 * @param element
	 * @return
	 */
	private RequestMappingInfo doCeateRequestMappingInfo(AnnotatedElement element) {
		AnnotationAttributes annotationAttributes = AnnotatedElementUtils.findMergedAnnotationAttributes(element, RequestMapping.class, false, false);
		RequestMapping requestMapping = AnnotationUtils.synthesizeAnnotation(annotationAttributes, RequestMapping.class, element);
		RequestMappingInfo.Builder builder = new RequestMappingInfo.Builder()
				 .buildPaths(requestMapping.path())
				 .buildMethods(requestMapping.method())
				 .buildParams(requestMapping.params())
				 .buildHeaders(requestMapping.headers())
				 .buildConsumes(requestMapping.consumes())
				 .buildProduces(requestMapping.produces());
		RequestMappingInfo requestMappingInfo = builder.build();
		return requestMappingInfo;
	}
	/**
	 *	构建PermissionInfo，从RequiresPermissions注解解析，如果无RequiresPermissions
	 *	则从RequiresRoles注解解析
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param element
	 * @return
	 */
	private PermissionInfo doCreatePermissionInfo(AnnotatedElement element) {
		RequiresPermissions requiresPermissions = element.getDeclaredAnnotation(RequiresPermissions.class);
		PermissionInfo permissionInfo = requiresPermissionsParse(requiresPermissions);
		if(permissionInfo==null) {
			RequiresRoles requiresRoles = element.getDeclaredAnnotation(RequiresRoles.class);
			permissionInfo = requiresRolesParse(requiresRoles);
		}
		return permissionInfo;
	}
	/**
	 *  从RequiresPermissions解析出权限标识
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param requiresPermissions
	 * @return
	 */
	private PermissionInfo requiresPermissionsParse(RequiresPermissions requiresPermissions) {
		if(requiresPermissions==null) {
			return null;
		}
		PermissionInfo permissionInfo = new PermissionInfo();
		permissionInfo.setPermissions(requiresPermissions.value());
		permissionInfo.setLogical(requiresPermissions.logical());
		return permissionInfo;
	}
	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param requiresRoles
	 * @return
	 */
	private PermissionInfo requiresRolesParse(RequiresRoles requiresRoles) {
		if(requiresRoles==null) {
			return null;
		}
		PermissionInfo permissionInfo = new PermissionInfo();
		permissionInfo.setRoles(requiresRoles.value());
		permissionInfo.setLogical(requiresRoles.logical());
		return permissionInfo;
	}
	/**
	 * 判断方法上是否有@RequestMapping注解
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param element
	 * @return
	 */
	@SuppressWarnings("unchecked")
	protected boolean isMapping(AnnotatedElement element) {
		for(Class<?> mappingClass : MAPPPING_TYPES) {
			if(AnnotatedElementUtils.hasAnnotation(element, (Class<? extends Annotation>) mappingClass)) {
				return true;
			}
		}
		return false;
	}
	/**
	 * 判断方法上是否有shiro注解
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param element
	 * @return
	 */
	@SuppressWarnings("unchecked")
	protected boolean isPermission(AnnotatedElement element) {
		for(Class<?> permissionClass : PERMISSSION_TYPES) {
			if(AnnotatedElementUtils.hasAnnotation(element, (Class<? extends Annotation>) permissionClass)) {
				return true;
			}
		}
		return false;
	}
}
