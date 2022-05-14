# nCoV-Hitcarder-ZJU

本项目基于 [Tishacy](https://github.com/Tishacy) 同学的 [ZJU-nCov-Hitcarder](https://github.com/Asudy/ZJU-nCov-Hitcarder) 项目，由本人修改而来，非常感谢 Tishacy 同学～

## Changelog

- **2022.5.7：** 已支持获取、识别、自动填写表单中的验证码。
- **2022.5.8：** 添加验证码失败重试（目前重试次数 hard-code 为 5 次，测试中）

- **2022.5.8：** 支持通过命令行参数 `-f` / `--config-file` 指定脚本运行读取的配置文件（模板 [config.json.templ](https://github.com/Asudy/nCoV-Hitcarder-ZJU/blob/master/config.json.templ)）

    1.   从模板复制一份你将使用的配置文件

         ```bash
         $ cp config.json.templ config-example.json
         ```

    2.   编辑新的配置文件，填写相应信息，保存退出

    3.   安全起见，可以调整配置文件权限设置

         ```bash
         $ chmod 600 config-example.json
         ```
    
    4.   运行脚本
    
         ```bash
         $ python3 hitcarder.py -f config-example.json
         # OR:
         $ python3 hitcarder.py --config-file config-example.json
         ```



以下是原 README。

---

# ZJU-nCov-Hitcarder

浙大nCov肺炎健康打卡定时自动脚本

 - 可定时，默认为每天6点5分
 - 默认每次提交上次所提交的内容（只有时间部分更新）
 - 系统表单如有更新，在当天自行手机打卡，后面会自动按照你更新后的选项继续打卡

 项目用于学习交流，仅用于各项无异常时打卡，如有身体不适等情况还请自行如实打卡~

<img src="https://github.com/Asudy/nCoV-Hitcarder-ZJU/raw/master/demo.png" width="500px"/>

> 感谢[conv1d](https://github.com/conv1d)同学，已使用requests直接登录浙大统一认证平台，不再依赖phantomjs

## Usage

1. clone本项目（为了加快clone速度，可以指定clone深度`--depth 1`，只克隆最近一次commit），并cd到本目录
    ```bash
    $ git clone https://github.com/Tishacy/ZJU-nCov-Hitcarder.git --depth 1
    $ cd ZJU-nCov-Hitcarder
    ```
    
2. 安装依赖

    ```bash
    $ pip3 install -r requirements.txt
    ```

3. 将config.json.templ模板文件重命名为config.json文件，并修改 config.json中的配置
  
    ```javascript
    {
        "username": "你的浙大统一认证平台用户名",
        "password": "你的浙大统一认证平台密码",
        "schedule": {
            "hour": "6",    // 6点
            "minute": "5"   // 5分 
        }
    }
    ```

4. 启动定时自动打卡脚本

   ```bash
   $ python3 hitcarder.py
   ```


## Tips

- 为了防止电脑休眠或关机时程序不运行，推荐把这个部署到VPS上
- 测试程序是否正常运行：可以先把定的时间放在最近的一个时间（比如下一分钟）看下到时间是否可以正常打卡
- 想指定自己打卡地理位置的童鞋可以参考[8#issue](https://github.com/Tishacy/ZJU-nCov-Hitcarder/issues/8#issue-565719250)


## Thanks

感谢贡献者

<a href="https://github.com/conv1d"><img src="https://avatars2.githubusercontent.com/u/24759956" width="100px" height="100px"></a>
<a href="https://github.com/Mythologyli"><img src="https://avatars.githubusercontent.com/u/15955880" width="100px" height="100px"></a>


## LICENSE

Copyright (c) 2020 tishacy.

Licensed under the [MIT License](https://github.com/Tishacy/ZJU-nCov-Hitcarder/blob/master/LICENSE)



