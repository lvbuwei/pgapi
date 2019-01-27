
#ifndef NGX_UNESCAPE_URI_COMPONENT
#define NGX_UNESCAPE_URI_COMPONENT  0
#endif

#ifndef NGX_HTTP_MAX_ARGS
#define NGX_HTTP_MAX_ARGS 100
#endif

#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_buf.h>
#include <ngx_module.h>
#include <ngx_conf_file.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>

#include <libpq-fe.h>
#include "cJSON.h"

typedef struct {
  ngx_str_t pguri;
  ngx_flag_t request_body;
} ngx_http_pgapi_loc_conf_t;

typedef struct {
    ngx_int_t     status;
} ngx_http_pgapi_ctx_t;


static void *ngx_http_pgapi_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_pgapi_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_pgapi_init(ngx_conf_t *cf);

// 创建配置结构体
static void *ngx_http_pgapi_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_pgapi_loc_conf_t *conf;
  conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_pgapi_loc_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }
  return conf;
}

//模块上下文结构
static ngx_http_module_t ngx_http_pgapi_module_ctx = {
  NULL,
  ngx_http_pgapi_init,
  NULL,
  NULL,

  NULL,
  NULL,

  ngx_http_pgapi_create_loc_conf,
  NULL
};

//解析指令
static ngx_int_t ngx_http_pgapi_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *clcf;
  clcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
  h = ngx_array_push(&clcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_pgapi_handler;
  return NGX_OK;
}

static ngx_command_t ngx_http_pgapi_commands[] = {
  {
    ngx_string("pgapi"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_pgapi_loc_conf_t,pguri),
    NULL
  },
  {
    ngx_string("pgapi_request_body"),
    NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_pgapi_loc_conf_t,request_body),
    NULL},
  ngx_null_command
};

ngx_module_t ngx_http_pgapi_module = {
  NGX_MODULE_V1,
  &ngx_http_pgapi_module_ctx,
  ngx_http_pgapi_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void ngx_http_pgapi_body_handler(ngx_http_request_t *r)
{
  ngx_chain_t *cl;
  r->main->count--;
  if (r->request_body == NULL) {
    ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }
  cl = r->request_body->bufs;
  if (cl != NULL){
    while (cl != NULL) {
      if (cl == r->request_body->bufs) {
        r->request_body->buf = cl->buf;
      } else {
        size_t old_len = r->request_body->buf->last - r->request_body->buf->pos;
        size_t next_len= cl->buf->last - cl->buf->pos;
        ngx_buf_t * buf = ngx_create_temp_buf(r->pool,old_len+next_len);
        ngx_memcpy(buf->pos,r->request_body->buf->pos,old_len);
        ngx_memcpy(buf->pos+old_len,cl->buf->pos,next_len);
        buf->last = buf->pos + old_len+next_len;
        r->request_body->buf = buf;
      }
      cl = cl->next;
    }
  }
}

static ngx_int_t ngx_http_pgapi_handler(ngx_http_request_t *r)
{
  const char *conninfo;
  PGconn *conn;
  PGresult *res;
  int fnamelen;
  int len;
  cJSON *root;
  cJSON *headers;
  cJSON *query;
  cJSON *body;
  char method[10]={0};
  char *sJson;
  ngx_http_pgapi_loc_conf_t *cf;
  
  u_char *buf;
  u_char *last;
  u_char *p,*q;
  unsigned parsing_value;
  u_char *src;
  u_char *dst;
  u_char *headkey,*headval;
  int iArgsCount;
  ngx_chain_t *cl;
  ngx_int_t rc;
  //只处理主请求,即客户端的真实请求,避免子请求造成的错误
  if (r != r->main) {
    return NGX_DECLINED;
  }
  cf = ngx_http_get_module_loc_conf(r,ngx_http_pgapi_module);
  //连接数据库
  conninfo = (char *) cf->pguri.data;
  conn = PQconnectdb(conninfo);
  if (PQstatus(conn) != CONNECTION_OK)
  {
    ngx_log_error(NGX_LOG_ERR,r->connection->log,0,
        "Connect to database failed:%s",PQerrorMessage(conn));
    PQfinish(conn);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  //创建json对象
  root = cJSON_CreateObject();  
  if (!root) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  cJSON_AddItemToObject(root,"headers",headers=cJSON_CreateObject());
  cJSON_AddItemToObject(root,"query",query=cJSON_CreateObject());
  cJSON_AddItemToObject(root,"body",body=cJSON_CreateObject());
  sJson = NULL;
  //获取真正的IP
  p = ngx_palloc(r->pool,r->connection->addr_text.len);
  p = r->connection->addr_text.data;
  p[r->connection->addr_text.len]='\0';
  cJSON_AddItemToObject(root,"ip",cJSON_CreateString((char *)p));
  /*if (r->method & (NGX_HTTP_GET)) {
    rc = ngx_http_discard_request_body(r);
    if (r != NGX_OK) {
      return rc;
    }
  }*/
  //获取请求体
  if (r->method & (NGX_HTTP_POST)) {
    //要求读到body数据,读取完成后回调函数
    rc = ngx_http_read_client_request_body(r,ngx_http_pgapi_body_handler);
    if (rc == NGX_AGAIN) {
      r->main->count++;
      return rc;
    }
    if (rc != NGX_OK) {
      r->main->count--;
      return rc;
    }
    r->main->count++;
    //return rc;
    return NGX_DONE;
  };
  
  if (r->request_body) {
    cl = r->request_body->bufs;
    if (cl->next == NULL) {
      len = cl->buf->last - cl->buf->pos;
      if (len == 0) {
        cJSON_AddItemToObject(body,"host",cJSON_CreateString(""));
      }
      p = ngx_palloc(r->pool,len);
      p = cl->buf->pos;
      p[len] ='\0';
      cJSON_AddItemToObject(body,"body",cJSON_CreateString((char *)p));
    }
  }

  // 增加method字段
  ngx_memcpy(method,r->method_name.data,r->method_name.len);
  cJSON_AddItemToObject(root,"method",cJSON_CreateString(method));
  
  //增加url字段
  buf = ngx_palloc(r->pool,r->uri.len);
  ngx_memcpy(buf, r->uri.data,r->uri.len);
  cJSON_AddItemToObject(root,"uri",cJSON_CreateString((char *)buf));

  //获取header部分内容
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  ngx_uint_t i = 0;
  part = &r->headers_in.headers.part;
  header = part->elts;
  for (i=0;/*void*/; i++)
  {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }
    headkey = ngx_palloc(r->pool,header[i].key.len);
    ngx_memcpy(headkey, header[i].lowcase_key,header[i].key.len);
    headval = ngx_palloc(r->pool,header[i].value.len);
    ngx_memcpy(headval, header[i].value.data,header[i].value.len);
    cJSON_AddItemToObject(headers,(char *)headkey,cJSON_CreateString((char *)(headval)));
  } 
  if (r->args.len > 0) {
    buf = ngx_palloc(r->pool,r->args.len);
    if (buf == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf,r->args.data,r->args.len);
    last = buf + r->args.len;
    p = buf;
    iArgsCount = 0;
    parsing_value = 0;
    q = p;
    headkey = NULL; headval = NULL;

  while (p != last) {
    if (*p == '=' && !parsing_value) {
      src = q; dst = q;
      ngx_unescape_uri(&dst,&src,p-q,NGX_UNESCAPE_URI_COMPONENT);
      headkey = ngx_palloc(r->pool,dst - q);
      ngx_memcpy(headkey,(char *)q,dst - q);
      p++;
      q = p;
      parsing_value = 1;
    } else if (*p == '&') {
      src = q; dst = q;
      ngx_unescape_uri(&dst, &src, p - q,NGX_UNESCAPE_URI_COMPONENT);
      headval = ngx_palloc(r->pool,dst - q);
      ngx_memcpy(headval,(char *)q,dst - q);
      p++;
      q=p;
      if (parsing_value) {
        parsing_value = 0;
        if (strlen((char *)headkey)>0) {
          cJSON_AddItemToObject(query,(char *)headkey,cJSON_CreateString((char *)(headval)));
          iArgsCount++;
        }
      } else {
        cJSON_AddItemToObject(query,(char *)headval,cJSON_CreateString(""));
        iArgsCount++;
      }
      if (iArgsCount == NGX_HTTP_MAX_ARGS) {
        break;
      }
    } else {
      p++;
    }
  }
  if (p != q || parsing_value) {
    src = q; dst = q;
    ngx_unescape_uri(&dst, &src, p - q, NGX_UNESCAPE_URI_COMPONENT);
    if (parsing_value) {
      if (strlen((char *)headkey)>0) {
        headval = ngx_palloc(r->pool,dst - q);
        ngx_memcpy(headval,(char *)q,dst - q);
        cJSON_AddItemToObject(query,(char *)headkey,cJSON_CreateString((char *)(headval)));
        iArgsCount++;
      }
    } else {
      if (dst - q) {
        cJSON_AddItemToObject(query,(char *)headkey,cJSON_CreateString(""));
        iArgsCount++;
      }
    }
  }
}
  sJson = cJSON_PrintUnformatted(root);
  buf = ngx_palloc(r->pool,strlen(sJson)+24);
  ngx_snprintf(buf, strlen(sJson)+24,"CALL proc_api_test('%s')",sJson);
  res = PQexec(conn,(char *)buf);
  if (PQresultStatus(res) != PGRES_TUPLES_OK)
  {
    PQclear(res);
    ngx_log_error(NGX_LOG_ERR,r->connection->log,0,
        "Fetch data failed:%s",PQerrorMessage(conn));
    PQfinish(conn);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_str_t type = ngx_string("application/json; charset=UTF-8");
  r->headers_out.status = NGX_HTTP_OK;
  fnamelen = 0;
  fnamelen = PQgetlength(res,0,0);
  r->headers_out.content_length_n = fnamelen;
  r->headers_out.content_type = type;

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    return rc;

  ngx_buf_t *b;
  b = ngx_create_temp_buf(r->pool,fnamelen);
  if (b == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  ngx_memcpy(b->pos,PQgetvalue(res,0,0),fnamelen);
  b->last = b->pos + fnamelen;
  b->last_buf = 1;
  PQclear(res);
  PQfinish(conn);

  ngx_chain_t out;
  out.buf = b;
  out.next =NULL;
  return ngx_http_output_filter(r,&out);
}
