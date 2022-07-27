
# Kong API Gateway
## Introduction
[Kong Gateway](https://docs.konghq.com/gateway/latest/) is a lightweight, fast, and flexible cloud-native API gateway. An API gateway is a reverse proxy that lets you manage, configure, and route requests to your APIs.

## Advantages
- Easy to install and maintain
- Have a GUI
- Flexible and Custom Plugins
- Api blueprint
- Great performance
- Security and Load balancing
- Documentation is clear

## Installation
- [official document](https://docs.konghq.com/gateway/latest/install-and-run/)
- install with docker
  - create a custom network
   ```
   docker network create kong-net
   ```
  -  create Postgres DB
  
    ```
    docker run -d --name kong-database \
    --network=kong-net \
    -p 5432:5432 \
    -e "POSTGRES_USER=kong" \
    -e "POSTGRES_DB=demo" \
    -e "POSTGRES_PASSWORD=kongpass" \
    postgres:9.6
    ```
  - initiate Kong SQL
    
  ```
    docker run --rm --network=kong-net \
    -e "KONG_DATABASE=postgres" \
    -e "KONG_PG_HOST=kong-database" \
    -e "KONG_PG_PASSWORD=kongpass" \
    -e "KONG_PG_DATABASE=demo" \
    -e "KONG_PASSWORD=test" \
    kong/kong-gateway:2.8.1.2-alpine kong migrations bootstrap
  ```

  - create Kong gateway
   ```
   docker run -d --name kong-gateway \
    --network=kong-net \
    -e "KONG_DATABASE=postgres" \
    -e "KONG_PG_HOST=kong-database" \
    -e "KONG_PG_USER=kong" \
    -e "KONG_PG_PASSWORD=kongpass" \
    -e "KONG_PG_DATABASE=demo" \
    -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
    -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
    -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
    -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
    -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
    -e "KONG_ADMIN_GUI_URL=http://localhost:8002" \
    -e KONG_LICENSE_DATA \
    -p 8000:8000 \
    -p 8443:8443 \
    -p 8001:8001 \
    -p 8444:8444 \
    -p 8002:8002 \
    -p 8445:8445 \
    -p 8003:8003 \
    -p 8004:8004 \
    kong/kong-gateway:2.8.1.2-alpine
   ```

## Kong's ports
- `8000`: listens for incoming HTTP traffic from your clients, and forwards it to your upstream services.
- `8001`: Admin API listens for calls from the command line over HTTP.
- `8443`: listens for incoming HTTPS traffic. This port has a similar behavior to 8000, except that it expects HTTPS traffic only. This port can be disabled via the configuration file.
- `8444`: Admin API listens for HTTPS traffic.

## Kong's commands
- kong stop: stop kong gateway
- kong reload: reload configuration of kong gateway
- kong start: start kong gateway
- kong check: Check the validity of a given Kong configuration file
- kong config: Use declarative configuration files with Kong.
- kong health: Check if the necessary services are running for this node.
- kong restart: This command is equivalent to doing both 'kong stop' and
'kong start'.

## Tutorial
### **Simple API Gateway**
The Kong can only use `Route` and `Service` to route traffic to backend service as below diagram. Let's take an simple example.
![xxx](./simple-gateway.png)
- Setup 2 backend services
  - let's using http://mockbin.org/
  - create **service-1**
  ![xxx](./service-1.PNG)
  - create **service-2**
  ![xxx](./service-2.PNG)
- Add services via Kong Manager
  ![xxx](./add_services.PNG)
- Add routes for services, 
    - `/user` -> `service-1`
    - `/transaction` -> `service-2`
    - `/features` -> `service-2`
  ![xxx](./add_routes.PNG)
- Testing
  - request path `/user` e.g. `http://localhost:8001/user`. The API gateway will route to `service-1` as below:
  ![xxx](./req_service-1.PNG)
  `http://localhost:8443/user` as below:
  ![xxx](./https_req_service-1.PNG)
  - request path `/transaction` e.g. `http://localhost:8001/transaction`. The API gateway will route to `service-2` as below:
  ![xxx](./req_service-2.PNG)
  - same case as path `/features`
  ![xxx](./req_service-3.PNG)
  `http://localhost:8443/features` as below:
  ![xxx](./https_req_service-3.PNG)
  - Kong API gateway log from docker:
  ![xxx](./log.PNG)

### **Authentication**
The Kong support many authentication through plugin,
let's take `Basic Authentication` as an example.
- Enable Auth Plugin
  ![xxx](./enable_basic_auth.PNG)
- Select scope of Auth, it can be `global` which controlled all services, or `scope` which controlled by service or route.
  ![xxx](./basic_auth_scope.PNG)
- Add consumer
    > Consumers are associated to individuals using your Service, and can be used for tracking, access management, and more.
    - add several consumers
    ![xxx](./add_consumers.PNG)
    - select consumer to add `Basic Authentication`
    ![xxx](./add_basic_auth.PNG)
    - fill fill username and password
    ![xxx](./user_pwd.PNG)
    - after add user and pwd
    ![xxx](./added_basic_auth.PNG)
- Testing
  - request `/user` with invalid authentication
  ![xxx](./req_with_basic_auth1.PNG)
  ![xxx](./req_with_basic_auth2.PNG)
  - request `/user` with valid authentication
  ![xxx](./req_with_basic_auth3.PNG)
  ![xxx](./req_with_basic_auth4.PNG)


### **Rate Limiting**
- Enable Rate Limiting Plugin
![xxx](./rate_limit_plugin.PNG)
- Config Rate Limiting
![xxx](./rate_limit.PNG)
  - `Config.Minute` means 2 req/minute
  - `Config.Second` means n req/second
- Testing
  - request `/user` with reachig to rate limit
  ![xxx](./rate_limit_max.PNG)

### **Load Balance**
> In Kong Gateway, an Upstream Object represents a virtual hostname and can be used to health check, circuit break, and load balance incoming requests over multiple services (targets).The workflow as below diagram:![xx](load_balancing.png)

 - Create backend services: `backend-service-1` and `backend-service-2`, here we are taking simple `echo-server` as backend service which output request simply.
    ```
    root@EPCNCHEW0116:~# docker run -d --name backend-service-1 -p 6001:8080 jmalloc/echo-server 
    314c0e734debc22d89302c29ff0d83de9746c4858bce8f380d6c4d87a9e08d8e
    root@EPCNCHEW0116:~#

    root@EPCNCHEW0116:~# docker run -d --name backend-service-2 -p 6002:8080 jmalloc/echo-server 
    304c0e734debe22d89302c29ff0d83de9746c4858bce8f380d6c4d87a9e08d8e
    root@EPCNCHEW0116:~#

    ```
    Find out local IP:
    ```
    root@EPCNCHEW0116:~# ip a|grep eth0 
    4: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 172.27.72.37/20 brd 172.27.79.255 scope global eth0
    root@EPCNCHEW0116:~#

    ```
    So the host:port of `backend-service-1` should be `172.27.72.37:6001`, `172.27.72.37:6002` for `backend-service-2`
 - Create **Upstream** via GUI, fill the name `my.first.upstream` as example and create.
   ![xxx](./create_upstream.PNG)
   ![xxx](./edit_upstream.PNG)
 - Edit **Upstream** and create **Target**, fill the host/ip and port and traffic weight of backend service.
   ![xxx](./create_upstream_target.PNG)
   Add more **target** if you want:
   ![xxx](./create_upstream_overview.PNG)
 - Create **Service** via GUI, fill the host with upstream name `my.first.upstream` or fill URL with `http://my.first.upstream:80`
   ![xxx](./load_balancing_service_create.PNG)
   ![xxx](./load_balancing_service_overview.PNG)

 - Create **Route** for service we created in last step and Route Path we take `/loadbalance` as example.
  ![xx](./load_balancing_route.PNG)
  ![xx](./load_balancing_route_overview.PNG)

 - Testing
   - request `http://localhost:8000/loadbalance` or with path `/loadbalance/a/b/c`, the first request would route to `backend-service-1`.
  ![xxx](./load_balancing_to_service_1.PNG)
    - The second request would route to `backend-service-2`
      ![xxx](./load_balancing_to_service_2.PNG)

## **Using Admin API**
- Configure a **Service**
  ```
  curl -i -X POST \
  --url http://localhost:8001/services/ \
  --data 'name=example-service' \
  --data 'url=http://mockbin.org'
  ```
- Add a **Route** for a **Service**
  ```
  curl -i -X POST \
  --url http://localhost:8001/services/example-service/routes \
  --data 'name=example' \
  --data 'paths[]=/example'
  ```
- Testing
  ```
  curl -i -X GET --url http://localhost:8000/example
  ```
- Create `Consumer`
  ```
  curl -i -X POST \
  --url http://localhost:8001/consumers/ \
  --data "username=Jason"
  ```
- Create a key for `Consumer`
  ```
  curl -i -X POST \
  --url http://localhost:8001/consumers/Jason/key-auth/ \
  --data 'key=ENTER_KEY_HERE'
  ```
- Verify key of `Consumer`
  ```
  curl -i -X GET \
  --url http://localhost:8000 \
  --header "Host: example.com" \
  --header "apikey: ENTER_KEY_HERE"
  ```

- Add a `Upstream`
  ```
  curl -X POST http://localhost:8001/upstreams \
  --data name=example_upstream
  ```
- Update `Service`
  ```
  curl -X PATCH http://localhost:8001/services/example_service \
  --data host='example_upstream'
  ```
- Add `Target`
  ```
  curl -X POST http://<admin-hostname>:8001/upstreams/example_upstream/targets \
  --data target='mockbin.org:80'

  curl -X POST http://<admin-hostname>:8001/upstreams/example_upstream/targets \
  --data target='httpbin.org:80'
  ```
