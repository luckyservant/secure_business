<table data-testid="renderer-table" data-number-column="false" data-table-width="760"><colgroup><col style="width: 252px;"><col style="width: 362px;"><col style="width: 142px;"></colgroup>

<tbody>

<tr>

<th rowspan="1" colspan="3" colorname="" class="ak-renderer-tableHeader-sortable-column__wrapper" data-colwidth="253,363,143" aria-sort="none">

<div class="ak-renderer-tableHeader-sortable-column">

**Security Controls**

</div>

</th>

</tr>

<tr>

<td rowspan="1" colspan="1" style="background-color: rgb(233, 242, 255);" colorname="Light blue" data-colwidth="253" data-cell-background="#deebff">

Control

</td>

<td rowspan="1" colspan="1" style="background-color: rgb(233, 242, 255);" colorname="Light blue" data-colwidth="363" data-cell-background="#deebff">

Description

</td>

<td rowspan="1" colspan="1" style="background-color: rgb(233, 242, 255);" colorname="Light blue" data-colwidth="143" data-cell-background="#deebff"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Secure by default**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="1">

<div id="1-0-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="1-0" aria-labelledby="1-0-wrapper" name="1-0" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="81" class="confluence-ssr-app-1tsmohl"><input type="checkbox" id="vehicle1" name="vehicle1" value="Bike">Enable security in the application with little to no configuration changes necessary, and security features available without additional cost from client’s end. Make visible indicators about the potential risks that may result from disabling secure by default settings and make those indicators known by implementing routine nudges that are built into the product <u data-renderer-mark="true">rather than relying on administrators</u></div>

</div>

</div>

<div data-task-local-id="2">

<div id="2-1-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="2-1" aria-labelledby="2-1-wrapper" name="2-1" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="484" class="confluence-ssr-app-1tsmohl"><input type="checkbox">Do not disable/circumvent default security settings on configs or frameworks settings</div>

</div>

</div>

<div data-task-local-id="3">

<div id="3-2-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="3-2" aria-labelledby="3-2-wrapper" name="3-2" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="571" class="confluence-ssr-app-1tsmohl">Do not expose any publicly accessible resource which are not supposed to be so and make sure no config/debug/comments are in place in public facing prod systems</div>

</div>

</div>

<div data-task-local-id="4">

<div id="4-3-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="4-3" aria-labelledby="4-3-wrapper" name="4-3" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="733" class="confluence-ssr-app-1tsmohl">Avoid over engineering, keep it simple</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Defence in Depth**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="5">

<div id="5-4-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="5-4" aria-labelledby="5-4-wrapper" name="5-4" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="805" class="confluence-ssr-app-1tsmohl">Implement checks on each layer (frontend, backend, os, network) so that the compromise of a single security control does not result in compromise of the entire system</div>

</div>

</div>

<div data-task-local-id="6">

<div id="6-5-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="6-5" aria-labelledby="6-5-wrapper" name="6-5" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="973" class="confluence-ssr-app-1tsmohl">Never mix input data with code statements (e.g: xss, sql injection vulns etc.)</div>

</div>

</div>

<div data-task-local-id="7">

<div id="7-6-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="7-6" aria-labelledby="7-6-wrapper" name="7-6" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1053" class="confluence-ssr-app-1tsmohl">Do not trust client/user, service supplied data and validate whenever possible within the “Zero Trust” context. Even data from our own resources (e.g db, files) are usual suspects</div>

</div>

</div>

<div data-task-local-id="8">

<div id="8-7-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="8-7" aria-labelledby="8-7-wrapper" name="8-7" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1234" class="confluence-ssr-app-1tsmohl">Notify Security team whenever integrating with 3rd party systems is needed</div>

</div>

</div>

<div data-task-local-id="9">

<div id="9-8-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="9-8" aria-labelledby="9-8-wrapper" name="9-8" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1310" class="confluence-ssr-app-1tsmohl">Validate outputs when necessary before returning to calling entity. This technique is known as “Canary Check”</div>

</div>

</div>

<div data-task-local-id="10">

<div id="10-9-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="10-9" aria-labelledby="10-9-wrapper" name="10-9" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1421" class="confluence-ssr-app-1tsmohl">Notify CloudOps and Security teams when new service/ports are needed to be introduced</div>

</div>

</div>

<div data-task-local-id="11">

<div id="11-10-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="11-10" aria-labelledby="11-10-wrapper" name="11-10" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1508" class="confluence-ssr-app-1tsmohl">Ensure integrity of application state with instruments such as CSRF tokens, HMAC codes, JWT tokens to prevent from input/state tampering</div>

</div>

</div>

<div data-task-local-id="12">

<div id="12-11-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="12-11" aria-labelledby="12-11-wrapper" name="12-11" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1646" class="confluence-ssr-app-1tsmohl">Identify features/code blocks that would introduce/alterbusiness Logic & flow and implement unit tests to cover risks</div>

</div>

</div>

<div data-task-local-id="13">

<div id="13-12-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="13-12" aria-labelledby="13-12-wrapper" name="13-12" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1766" class="confluence-ssr-app-1tsmohl">Business critical implementations must be reviewed by security champs or security team respectively before merging. Please request recommendations from security team when the risk is not clear</div>

</div>

</div>

<div data-task-local-id="14">

<div id="14-13-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="14-13" aria-labelledby="14-13-wrapper" name="14-13" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="1960" class="confluence-ssr-app-1tsmohl">Identify if the feature/application introduce new business logic that might be exploited if not properly validated (e.g., price calculations, eligibility checks)?</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Data Handling & Storage**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="35">

<div id="35-14-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="35-14" aria-labelledby="35-14-wrapper" name="35-14" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2161" class="confluence-ssr-app-1tsmohl">Identify and label sensitive data</div>

</div>

</div>

<div data-task-local-id="36">

<div id="36-15-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="36-15" aria-labelledby="36-15-wrapper" name="36-15" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2196" class="confluence-ssr-app-1tsmohl">Consider to avoid it if possible</div>

</div>

</div>

<div data-task-local-id="37">

<div id="37-16-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="37-16" aria-labelledby="37-16-wrapper" name="37-16" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2230" class="confluence-ssr-app-1tsmohl">D Employ best fit cryptography (encryption, hashing, masking etc.) during processing and storing</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Authentication & Authorization (Complete Mediation)**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="38">

<div id="38-17-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="38-17" aria-labelledby="38-17-wrapper" name="38-17" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2393" class="confluence-ssr-app-1tsmohl">How will users prove who they are? You want to make sure that someone cannot spoof a legitimate user (authentication)</div>

</div>

</div>

<div data-task-local-id="39">

<div id="39-18-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="39-18" aria-labelledby="39-18-wrapper" name="39-18" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2512" class="confluence-ssr-app-1tsmohl">Clearly identify and state **Who** should be allowed to access **What** resource</div>

</div>

</div>

<div data-task-local-id="40">

<div id="40-19-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="40-19" aria-labelledby="40-19-wrapper" name="40-19" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2586" class="confluence-ssr-app-1tsmohl">D Explicitly state publicly accessible resources</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Least Privilege**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="15">

<div id="15-20-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="15-20" aria-labelledby="15-20-wrapper" name="15-20" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2665" class="confluence-ssr-app-1tsmohl">Create identities/entities/services with bare minimum access by default</div>

</div>

</div>

<div data-task-local-id="16">

<div id="16-21-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="16-21" aria-labelledby="16-21-wrapper" name="16-21" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2738" class="confluence-ssr-app-1tsmohl">D Implement systems that propagates “Separation of Duties” principle with methods like RoleBasedAccessControl(RBAC)</div>

</div>

</div>

<div data-task-local-id="17">

<div id="17-22-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="17-22" aria-labelledby="17-22-wrapper" name="17-22" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="2855" class="confluence-ssr-app-1tsmohl">Enable access with “Need to See” approach by explicitly stating resource and access rights (tables name, read, update etc.) Exp: Accessing other customers' data or admin features from a regular account</div>

</div>

</div>

<div data-task-local-id="18">

<div id="18-23-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="18-23" aria-labelledby="18-23-wrapper" name="18-23" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3059" class="confluence-ssr-app-1tsmohl">Remove/disable unnecessary features/services/dependencies/code blocks</div>

</div>

</div>

<div data-task-local-id="19">

<div id="19-24-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="19-24" aria-labelledby="19-24-wrapper" name="19-24" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3130" class="confluence-ssr-app-1tsmohl">Validate if the entity has the right to execute requested operation?(e.g: Can a regular user operate an update for a particular field in which only admin users are granted to)</div>

</div>

</div>

<div data-task-local-id="20">

<div id="20-25-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="20-25" aria-labelledby="20-25-wrapper" name="20-25" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3307" class="confluence-ssr-app-1tsmohl">Enable multi-factor checks on critical functions</div>

</div>

</div>

<div data-task-local-id="21">

<div id="21-26-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="21-26" aria-labelledby="21-26-wrapper" name="21-26" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3357" class="confluence-ssr-app-1tsmohl">Do not use personal accounts to automate any stuff. Ask teams to provision service accounts</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Fail-Safe**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="22">

<div id="22-27-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="22-27" aria-labelledby="22-27-wrapper" name="22-27" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3473" class="confluence-ssr-app-1tsmohl">If validation fails then reject the input, do not attempt to cast, trim, wraparound the input that might lead to “Undefined Behaviours” within business logic</div>

</div>

</div>

<div data-task-local-id="23">

<div id="23-28-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="23-28" aria-labelledby="23-28-wrapper" name="23-28" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3632" class="confluence-ssr-app-1tsmohl">Ensure consistency during exception handling by IO disposals (exp:closing connections), re-initialisation of variables to their stable state</div>

</div>

</div>

<div data-task-local-id="24">

<div id="24-29-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="24-29" aria-labelledby="24-29-wrapper" name="24-29" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3774" class="confluence-ssr-app-1tsmohl">Ensure consistency during exception handling by IO disposals (exp:closing connections), re-initialisation of variables to their stable state</div>

</div>

</div>

<div data-task-local-id="25">

<div id="25-30-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="25-30" aria-labelledby="25-30-wrapper" name="25-30" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="3916" class="confluence-ssr-app-1tsmohl">Do not expose details which might include sensitive information in exception messages to clients during failures</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Open Design (Avoid security through obscurity)**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="26">

<div id="26-31-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="26-31" aria-labelledby="26-31-wrapper" name="26-31" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4090" class="confluence-ssr-app-1tsmohl">Act as if the mechanism is publicly known</div>

</div>

</div>

<div data-task-local-id="27">

<div id="27-32-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="27-32" aria-labelledby="27-32-wrapper" name="27-32" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4133" class="confluence-ssr-app-1tsmohl">Employ proper cryptography instruments when necessary. Exp: To prevent guessable tokens, a token stored in an insecure location with plain text format, cookie without Secure and HttpOnly flags</div>

</div>

</div>

<div data-task-local-id="28">

<div id="28-33-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="28-33" aria-labelledby="28-33-wrapper" name="28-33" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4327" class="confluence-ssr-app-1tsmohl">Never harcode data into the source code. Sensitive application credentials and tokens should be stored separately from the application’s source code</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Logging**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="29">

<div id="29-34-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="29-34" aria-labelledby="29-34-wrapper" name="29-34" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4498" class="confluence-ssr-app-1tsmohl">Authentication/authorisation events (success and failure)</div>

</div>

</div>

<div data-task-local-id="30">

<div id="30-35-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="30-35" aria-labelledby="30-35-wrapper" name="30-35" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4557" class="confluence-ssr-app-1tsmohl">CRUD operations on critical resources</div>

</div>

</div>

<div data-task-local-id="31">

<div id="31-36-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="31-36" aria-labelledby="31-36-wrapper" name="31-36" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4596" class="confluence-ssr-app-1tsmohl">Logs must include user ID, IP address, valid timestamp, type of action performed, and object of this action</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

<tr>

<td rowspan="1" colspan="1" colorname="" data-colwidth="253">

**Open Source Employment**

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="363">

<div data-task-list-local-id="" class="confluence-ssr-app-1h99aef">

<div data-task-local-id="32">

<div id="32-37-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="32-37" aria-labelledby="32-37-wrapper" name="32-37" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4741" class="confluence-ssr-app-1tsmohl">Align with teams before picking an open source dependency</div>

</div>

</div>

<div data-task-local-id="33">

<div id="33-38-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="33-38" aria-labelledby="33-38-wrapper" name="33-38" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4800" class="confluence-ssr-app-1tsmohl">Notify CloudOps and Security teams before introducing any customised containers to the application</div>

</div>

</div>

<div data-task-local-id="34">

<div id="34-39-wrapper" class="confluence-ssr-app-l9nhxs"><span contenteditable="false" class="confluence-ssr-app-7mj7cm"><input id="34-39" aria-labelledby="34-39-wrapper" name="34-39" type="checkbox"><span aria-hidden="true" style="--icon-primary-color: currentColor; --icon-secondary-color: var(--ds-surface, #FFFFFF);" class="confluence-ssr-app-snhnyn"></span></span>

<div data-component="content" data-renderer-start-pos="4900" class="confluence-ssr-app-1tsmohl">Regularly review and remove unused dependencies</div>

</div>

</div>

</div>

</td>

<td rowspan="1" colspan="1" colorname="" data-colwidth="143"></td>

</tr>

</tbody>

</table>
