use std::{ops::Add, time::Duration};

use rust_alipay_sdk::{
    alipay::AlipaySdkBuilder,
    error::AlipayResult,
    model::alipay_trade_pay_model::AlipayTradePayModel,
    product_code::ProductCode,
    request::{
        alipay_trade_pay_request::{AlipayTradePagePayRequest, ALIPAY_TRADE_PAGE_PAY},
        Method,
    },
    time::{now, to_time_string},
};

const PRIVATE_KEY: &str = "MIIEpQIBAAKCAQEAvO/5WOSR9YI2xyyL7WlGXw4iuBxWStLQCanXX+rq3Q1uhkote5sqNrXmKjbUYxF6LQppdSUM03X2+dv9MyxG7SbPMoYPTe54jK7yk7tAralNJWoQyDrnRoPJyDU1F/nDQkByZ06FS78r9JcN9M7JSRcsjQudYbkYoLVo7WIR23ommDYjKy5i2iuU2TsvnhHfpgCoBWObTq1W/QreGwQvyvZnRNy1xqSjztZAm+ChwHaggQIE7m0bF4p6TnzOHhgI0ymkEFnp5KTw8t+j1B2meAJc5VuhK418WF1sShalaIs37RHmQ4/N/AUHy4WItIWSXjPtDr1EUGWKRSAWDilLowIDAQABAoIBAHmO19lmbbYMShwJQBnGMr1zhcj4ilhnm+urt2MB7Iu+WY7S6MJvCVDb5TLhxfHbS8TwvvrclIz0h6sn65bh9NwdrQ8vi2czd6Hj6TQ9NJbGp1jcDeIVa7lFjyxdd0RusD7O4gwvS7l5TNl32kXYSU7aNxKkF2TJRtwW+2RHRX/z0ReHHjrkAD5QGfv4U0eLklCXiirbJTo6iFvL4pwWNFGCcRGBHiPrg77tLbj2h3WxEd5tBA4vBsiZBQVTFG9uPmg5b+aoaJDrrWLeLOQmJgAnLrwgMzKCj9douHL7sEowzOcCue3GElNyE/vrideqKrpdIRS7mPOXPYDLrPKk1EkCgYEA+AbbpQlYjw6Orbz2Zdws+atM+nxM0iE9KMOKU68D87SXp5oSm1OrSec6eeFCZ3xoe72PvePKGCGc7RQCdFK4md6ljqm8/TgL+ypopgm4iNLtruyaRg7BXF2kRP+uPVVPI3S1ls3vXa4ypJ1W1kFb2SZRXk/7IwONy9R16nGFs+8CgYEAwwLWrBeuuICo1+hA1YljfmHbCLgg0kObNgMgE3iw9UpqXaao6Dn0I01UNwlf495hbv09mWeempuiroDschnlXoLP3ao42Taik0cP27KjLTXF36h2LAZKzWDb2KM8yb186m1M/6wfm/2UdnaP8zGia5en6VAXTraGtWMvZwS4340CgYEAwwNZZd0AVZLjmjVOIu7IKhKHNxfOqxVZahi9RWkBmXewGiapZJmXv0bgkn4L4SRPXqPARlS5TNn48etetqln3gvSbmaFYy/TM8u3dn2EK4h1O6lq75SgcghqpZnHHRBbZgxYztbi0uypgwb3BQVku0tGhPosAu7DabWGdSyHLN8CgYEAltjwRAjBv7jOYs0mscdn7hA2BYWg5eUj/+DlBArdH7EjnDPZ/mEuB8y+cyBOS47u4ZME/lBYMJJpggD6ZbzAX55iur384ZFQqwpSKwkBDmzFFqBSYPWxETN2fBqxYACyywgngrKbdOfv2r8V1PI1CHM0kNbCYMHybAdAWLkfZNUCgYEAvrJdUPScy8qlUI6MWUW8AZdHegP+t+W+o6k0+5ia8Ha+Xe6HNo1/mTUyxH1KVANQkOA/3lk2ZXxzRxCUwAdnTaLZfKfTFlasThbegaHzglwTy3nTf4PpNxF4lHA38UvCUNO/aZGaHMNtTzh8KYMpHcvUa7J0kLRmMtVoc0rkk3Y=";
const ALIPAY_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0I0AVwLW7t9hZaV750AEjLOC+x/5rZCQFf7CYN3EEb5Fdb4Xe0Eblh/mGDpFUnsguYMTC6DCyelT9RVKn0ajFynXVXuivXYjDXWxN/mHl90CSEuAHWZOiPtQO6cwyXv5y/8urj0FvFDLE8uzMn84fBk2qqnTvV0VtwCdSUcEp4ByqeG/2SDCj9NK/iqUV516iZXfXwdvkTacdd6ONZVo/r+umX/wb7S0HBh+rr5CKQmSzS0I/SpmOwyQjeomZHdAAPzujCqEGtACAoSwzyyjFXRvhLUhd2ly7HN8J6wSiWvpqR/7Ds+E+SjdaXFHQDUvMtwXNTZmqclwNIvklYI1/QIDAQAB";

const APP_ID: &str = "9021000126650292";
const GATE_WAY: &str = "https://openapi-sandbox.dl.alipaydev.com/gateway.do";

fn main() -> AlipayResult<()> {
    let sdk = AlipaySdkBuilder::new(APP_ID, PRIVATE_KEY)
        .with_gateway(GATE_WAY)
        .build();

    let mut model = AlipayTradePayModel::new();
    model.set_out_trade_no("123456");
    model.set_total_amount(44.32);
    model.set_subject("支付宝测试");
    model.set_product_code(ProductCode::FastInstantTradePay);

    let now = now()?;
    let time_expire = now.add(Duration::from_secs_f64(60.0));

    model.set_time_expire(to_time_string(time_expire));

    let mut request = AlipayTradePagePayRequest::new(Method::GET, model);
    request.set_return_url("https://www.baidu.com")?;
    let form = request.create_form()?;

    let result = sdk.page_exec(ALIPAY_TRADE_PAGE_PAY, form)?;
    print!("{}", result);

    Ok(())
}
