### DESC
- this is a simple irc client for command line user
- can send msg fit the role of irc or use shortcut to effective
    | shortcut | desc |
    | - | - |
    | n | set nickname: /n mynickname} |
    | l | login(need set nickname first): /l} |
    | j | join channel: /j #ubuntu} |
    | L | leave channel: /L} |
    | q | quit from irc: /q} |
    | N | list name from channel: /N} |
    | c | list channel or topic: /c} |
    | i | invite other to channel: /i other-nickname} |
    | k | kick other out of channel: /k other-nickname} |
    | m | send msg in cur channel: /m helloworld} |
    | M | send msg to other channel} |
    | p | talk to other user: /p other-nickname hi?} |
    | w | search user} |
    | W | search user info} |

### deps
- platform: linux (ubuntu)
- lib: libc + pthread

### compile
- ``` gcc main.c -o irc-client -lpthread ```
- ``` gcc unix-domain-socket-client.c -o usocket ```

### Usage
- open terminal, first setup irc-client: ``` ./irc-client [{ip/host} [{port}]] ```, default irc server: adams.freenode.net, port 6667
    + this terminal used to show msg from irc
- open other terminal, type: ``` ./usocket IRC_Server ```
    + this terminal used to input
- after connect success
    - set nickname,  type: ```/n mynickname ```
    - login, type: ```/l ```
    - join ``` #ubuntu ``` channel, type ```/j #ubuntu ```
    - then start chat: ```/m hi? ``` or whatever

