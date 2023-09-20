package com.duke.security.mvc;

import com.duke.common.base.utils.CollectionUtils;
import com.duke.common.base.utils.SnowflakeUtils;
import com.duke.common.base.utils.StringUtils;
import com.duke.security.common.sys.resource.Resource;
import com.duke.security.common.sys.resource.ResourceService;
import com.duke.security.common.sys.resource.ResourceTypeEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPattern;

import java.math.BigDecimal;
import java.util.*;

@Component
public class ResourceScanner implements ApplicationListener<ContextRefreshedEvent> {
    @Autowired
    private RequestMappingHandlerMapping mappingInfo;
    @Autowired
    private ResourceService resourceService;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void onApplicationEvent(ContextRefreshedEvent event) {
        ApplicationContext context = event.getApplicationContext();
        if (context.getParent() != null) {
            return;
        }
        Map<RequestMappingInfo, HandlerMethod> map = mappingInfo.getHandlerMethods();
        List<Resource> resources = resourceService.queryOperationResources();
        // 分布式环境下这里需要分布式协调，下面这行和上面这行不能交换位置
        int count = resourceService.changeOperationResourcesToInitializing();
        Map<String, Resource> resourceMap = new HashMap<>();
        List<Resource> resourcesToInsert = new ArrayList<>(map.size());
        List<BigDecimal> resourcesToRecovery = null;
        if (CollectionUtils.isNotEmpty(resources)) {
            int size = resources.size();
            resourceMap = new HashMap<>(CollectionUtils.hashMapInitialCapacity(size));
            for (Resource resource : resources) {
                resourceMap.put(resource.getMethodes() + "@" + resource.getPathes(), resource);
            }
            resourcesToRecovery = new ArrayList<>(size);
        }

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : map.entrySet()) {
            RequestMappingInfo mapping = entry.getKey();
            HandlerMethod handlerMethod = entry.getValue();
            ResourceDescription description = handlerMethod.getMethodAnnotation(ResourceDescription.class);
            PathPatternsRequestCondition condition = mapping.getPathPatternsCondition();
            RequestMethodsRequestCondition httpMethod = mapping.getMethodsCondition();
            Set<RequestMethod> methods = httpMethod.getMethods();
            String[] requestMethods = new String[methods.size()];
            int index = -1;
            if (methods.size() > 0) {
                for (RequestMethod requestMethod : methods) {
                    requestMethods[++index] = requestMethod.name();
                }
                quickSort(requestMethods, 0, requestMethods.length - 1);
            }
//            PatternsRequestCondition condition = mapping.getPatternsCondition();
//            Set<String> directPaths = mapping.getDirectPaths();
//            Set<String> patterns = condition.getPatterns();
            Set<PathPattern> patterns = condition.getPatterns();
            String[] pathes = new String[patterns.size()];

            if (!CollectionUtils.isEmpty(patterns)) {
                index = -1;
                for (PathPattern path : patterns) {
                    pathes[++index] = path.getPatternString();
                }
                quickSort(pathes, 0, pathes.length - 1);
                Resource resource;
                if ((resource = resourceMap.get(StringUtils.join(requestMethods, ",") + "@" + String.join(",", pathes))) != null) {
                    resourcesToRecovery.add(resource.getId());
                } else {
                    resourcesToInsert.add(Resource.builder()
                            .id(BigDecimal.valueOf(SnowflakeUtils.getDefaultSnowFlakeId()))
                            .name((description == null ? StringUtils.join(requestMethods, ",") + " " + String.join(",", pathes) : description.value()))
                            .pathes(String.join(",", pathes))
                            .methodes(StringUtils.join(requestMethods, ","))
                            .meta("{}")
                            .type(ResourceTypeEnum.OPERATION.getKey())
                            .general(Boolean.TRUE)
                            .enabled(Boolean.TRUE)
                            .tenantId(BigDecimal.ZERO)
                            .build());
                    System.out.println("insert into sys_resource (id, name, type, pathes, methodes, meta, general, enabled, tenant_id) values (" +
                            SnowflakeUtils.getDefaultSnowFlakeId() +
                            ", '" + (description == null ? StringUtils.join(requestMethods, ",") + " " + String.join(",", pathes) : description.value()) + "'" +
                            ", " + ResourceTypeEnum.OPERATION.getKey() +
                            ", '" + String.join(",", pathes) + "'" +
                            ", '" + StringUtils.join(requestMethods, ",") + "'" +
                            ", '{}'" +
                            ", true" +
                            ", true" +
                            ", 0);");
                }
            }
        }
        if (CollectionUtils.isNotEmpty(resourcesToRecovery)) {
            int total = resourceService.changeOperationResourcesToOK(resourcesToRecovery);
        }
        if (CollectionUtils.isNotEmpty(resourcesToInsert)) {
            int total = resourceService.insertResources(resourcesToInsert);
        }
        int total = resourceService.changeOperationResourcesToManualAfterInitializing();
    }

    static void quickSort(String[] arr, int left, int right) {
        String f, t;
        int rtemp, ltemp;

        ltemp = left;
        rtemp = right;
        f = arr[(left + right) / 2];
        while (ltemp < rtemp) {
            while (arr[ltemp].compareTo(f) < 0) {
                ++ltemp;
            }
            while (arr[rtemp].compareTo(f) > 0) {
                --rtemp;
            }
            if (ltemp <= rtemp) {
                t = arr[ltemp];
                arr[ltemp] = arr[rtemp];
                arr[rtemp] = t;
                --rtemp;
                ++ltemp;
            }
        }
        if (ltemp == rtemp) {
            ltemp++;
        }
        if (left < rtemp) {
            quickSort(arr, left, ltemp - 1);
        }
        if (ltemp < right) {
            quickSort(arr, rtemp + 1, right);
        }
    }
}
