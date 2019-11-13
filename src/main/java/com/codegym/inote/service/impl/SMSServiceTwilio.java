package com.codegym.inote.service.impl;

import com.codegym.inote.model.CodeOTP;
import com.codegym.inote.service.SMSService;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;

public class SMSServiceTwilio implements SMSService {
    private static final String ACCOUNT_SID = "AC1452421ac2f80d634e18cb400f2d3c91";
    private static final String AUTH_TOKEN = "285a4c93ce4f88711a5c3c13650484db";
    private CodeOTP otp = new CodeOTP();

    @Override
    public Message sendSMS() {
        Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
        int otp = (int) (100000 + Math.random() * (999999 - 100000));
        Message message = Message.creator(
                new com.twilio.type.PhoneNumber("+84382529310"),
                new com.twilio.type.PhoneNumber("+12563630467"),
                otp + "")
                .create();
        this.otp.setOtp(otp);
        return message;
    }
}
