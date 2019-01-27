# pgapi
nginx direct connect postgresql

此模块主要用来做rest json 接口，通过此模块，可以将数据库的存储过程直接映射成url地址，
nginx收到的url查询参数,也就是请求参数?后面查询参数转换成json类型,将header也转换成json
参数，一并发到存储过程做为存储过程参数，存储过程返回json输出参数,这样，接口服务器除了
需要安装nginx和postgresql,不用安装其他任何语言和框架，就可以提供rest的json服务。
想增加功能的，请加入QQ群:5276420

比如，如果发起请求/api/test?aaa=333&bbb=444

存储过程的param中将会收到如下的参数

```
{
  "ip":"127.0.0.1",
  "query":{
    "aaa":"333",
    "bbb":"444"
  },
  "headers":{
    "user_agent":"curl-1.7",
    "host":"localhost:80"
  }
}
```

如果数据库使用pg11以下，则只能使用function了，因为procedure是11才引入的。
此时，只需要修改代码,将call proc# 改成 select * from func_#即可。


接口实现方式，如下图所示。

```
CREATE OR REPLACE PROCEDURE proc_api_test(param jsonb,inout Result jsonb='{}')
AS
$$
DECLARE
  r record;
BEGIN
  --PERFORM 1 FROM pg_sleep(5);
  Result = '{"resid":0,"resmsg":"DB_OK"}';
  RETURN;
END;
$$
LANGUAGE plpgsql;

```
