<#-- Abgeleitet von base/login/error.ftl aus Keycloak 26.7.3 (die Version in
     compose.sso.yml und k8s/components/sso). Einziger Unterschied: der Abmelde-Link
     unten. Beim Keycloak-Upgrade gegen die neue base/login/error.ftl abgleichen.
     Die Adresse kommt aus url.loginUrl (<basis>/realms/<realm>/login-actions/
     authenticate), damit weder Realm noch Hostname noch Kontextpfad fest
     verdrahtet sind. Ohne Parameter zeigt der Logout-Endpunkt von Keycloak die
     Bestaetigungsseite fuer die Sitzung des Browsers. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${kcSanitize(msg("errorTitle"))?no_esc}
    <#elseif section = "form">
        <div id="kc-error-message">
            <p class="instruction">${kcSanitize(message.summary)?no_esc}</p>
            <#if traceId??>
                <p class="instruction" id="traceId">${msg("traceIdSupportMessage", traceId)}</p>
            </#if>
            <#if skipLink??>
            <#else>
                <#if client?? && client.baseUrl?has_content>
                    <p><a id="backToApplication" href="${client.baseUrl}">${msg("backToApplication")}</a></p>
                </#if>
            </#if>
            <p class="instruction" id="kc-error-logout">${msg("errorSignOutHint")} <a id="kc-error-logout-link" href="${url.loginUrl?keep_before("/login-actions/")}/protocol/openid-connect/logout">${msg("errorSignOutLink")}</a></p>
        </div>
    </#if>
</@layout.registrationLayout>
