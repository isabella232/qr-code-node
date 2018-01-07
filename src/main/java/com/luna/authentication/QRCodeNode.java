/*
 *
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 David Luna.
 *
 */

package com.luna.authentication;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.qr.GenerationUtils;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import java.util.Collections;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A node that displays a QR code, whose content is either free-text or a URI.
 *
 * Values can be read from the sharedState to display in the QR code.
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = QRCodeNode.Config.class)
public class QRCodeNode extends SingleOutcomeNode {

    private final Config config;
    private final static Pattern FREETEXT_REPLACE = Pattern.compile("\\{\\{(.*?)}}");

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100,  validators = {RequiredValueValidator.class} )
        default OperationMode operationMode() { return OperationMode.FreeText; }

        @Attribute(order = 200)
        default String freeText() { return ""; }

        @Attribute(order = 300)
        default String uriScheme() {
            return "";
        }

        @Attribute(order = 400)
        default String uriHost() { return ""; }

        @Attribute(order = 500)
        default String uriPort() { return ""; }

        @Attribute(order = 600)
        default String uriResource() { return ""; }

        @Attribute(order = 700)
        default Map<String, String> uriQueryParams() { return Collections.emptyMap(); }
    }

    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public QRCodeNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        return context.getCallback(ScriptTextOutputCallback.class)
                .map(ScriptTextOutputCallback::getMessage)
                .map(String::new)
                .filter(outputVal -> !StringUtils.isEmpty(outputVal))
                .map(outputVal -> goToNext().build())
                .orElseGet(() -> sendQRCode(context));
    }

    private Action sendQRCode(TreeContext context) {
        return Action.send(createQRCode(context)).build();
    }

    private Callback createQRCode(TreeContext context) {
        switch (config.operationMode()) {
            case URI:
                return buildUriQR(context);
            case FreeText:
            default:
                return buildFreetextQR(context);
        }
    }

    private Callback buildFreetextQR(TreeContext context) {

        String freeText = config.freeText();
        Matcher matcher = FREETEXT_REPLACE.matcher(freeText);

        while (matcher.find()) {
            String replace = matcher.group();
            String fieldName = replace.substring(2, replace.length() - 2);
            String value = context.sharedState.get(fieldName).asString();
            freeText = freeText.replaceFirst("\\{\\{" + fieldName + "}}", value);
        }

        return generateQRCallback(freeText);
    }

    private Callback generateQRCallback(String text) {
        return new ScriptTextOutputCallback(
                GenerationUtils.getQRCodeGenerationJavascriptForAuthenticatorAppRegistration(
                        "callback_0", text));
    }

    private Callback buildUriQR(TreeContext context) {
        StringBuilder builder = new StringBuilder()
                .append(config.uriScheme()).append("://")
                .append(config.uriHost()).append(":")
                .append(config.uriPort()).append("/")
                .append(config.uriResource()).append("?");

        config.uriQueryParams().forEach((k, v) -> {
            switch(v.substring(0, 1)) {
                case "&":
                    builder.append(k).append("=")
                            .append(context.sharedState.get(v.substring(1)).asString()).append("&");
                    return;
                default:
                    builder.append(k).append("=").append(v).append("&");
            }
        });

        builder.deleteCharAt(builder.length() - 1);

        return generateQRCallback(builder.toString());
    }

    /**
     * Enum representing different operation modes.
     */
    public enum OperationMode {
        FreeText,
        URI
    }
}