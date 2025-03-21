import sys
import time
import uuid
import configparser
import os
from datetime import datetime
from io import BytesIO
from hashlib import md5, sha1, sha256

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QTextEdit, QLineEdit,
    QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QFormLayout,
    QGridLayout, QMenu, QMenuBar, QDialog, QComboBox, QFileDialog, QCheckBox, QScrollArea
)
from PyQt6.QtGui import QAction,QFont
from PyQt6.QtCore import Qt

# 使用 PyMISP 库
try:
    from pymisp import PyMISP, AbstractMISPObjectGenerator, MISPAttribute, MISPTag
except ImportError:
    print("请先安装 PyMISP: pip install PyMISP")
    sys.exit(1)

import requests


# ------------------------------
# tag 颜色辅助函数
def custom_color_tag(tagg):
    """
    根据 tag 内容返回对应颜色  
    如果 tag 包含 "攻击" 返回红色，否则返回绿色
    """
    if "攻击" in tagg:
        return "#F279B7"
    else:
        return "#28A745"


# ------------------------------
# 服务器查重辅助函数（针对单个 IOC 的属性级别查重）
def is_ioc_duplicate(misp, value):
    """
    利用服务器查询 IOC 是否已存在。使用 misp.search() 查询属性，
    若返回结果中包含至少一个 Attribute，则认为该 IOC 已存在。
    """
    try:
        result = misp.search(value=value, controller="attributes")
        if result and "Attribute" in result and len(result["Attribute"]) > 0:
            return True
    except Exception as e:
        # 根据需要记录日志
        pass
    return False


# ------------------------------
# 改进后的更新 Event 的 tag 函数（使用 update_event 接口）
def update_event_tag(misp, event_id, listOfTagg):
    updated_tags = [{"name": str(tag), "color": custom_color_tag(tag)} for tag in listOfTagg]
    payload = {"Event": {"id": event_id, "Tag": updated_tags}}
    result = misp.update_event(payload)
    return result


# ------------------------------
# 其它辅助函数示例
def push_event_to_misp(jsonEvent):
    # 示例：上传 event 的代码
    print("Push event to MISP:", jsonEvent)
    pass

def upload_file():
    # 示例：上传文件的代码
    print("Upload file")
    pass

def get_taxonomy(iocfileparse):
    # 示例：根据 iocfileparse 解析 tag，返回 tag 列表
    return ["APT", "攻击"]


# ------------------------------
# Event上传对话框（增加“检查重复事件”复选框，同时添加事件级别查重逻辑）
class EventUploadDialog(QDialog):
    def __init__(self, misp, event_config, parent=None):
        super().__init__(parent)
        self.misp = misp
        self.event_config = event_config
        self.setWindowTitle("Event Upload")
        self.setGeometry(450, 300, 700, 650)
        self.init_ui()
        
    def init_ui(self):
        grid = QGridLayout()
        grid.setSpacing(10)
        row = 0
        
        # 事件描述（info）占用整行
        lbl_desc = QLabel("描述：")
        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("请输入描述（将作为事件 info）")
        self.desc_input.setFixedHeight(80)
        grid.addWidget(lbl_desc, row, 0)
        grid.addWidget(self.desc_input, row, 1, 1, 3)
        row += 1

        # URL 和 IP 分两列
        lbl_url = QLabel("URL：")
        self.url_input = QTextEdit()
        self.url_input.setPlaceholderText("每行一个")
        self.url_input.setFixedHeight(60)
        grid.addWidget(lbl_url, row, 0)
        grid.addWidget(self.url_input, row, 1)

        lbl_ip = QLabel("IP：")
        self.ip_input = QTextEdit()
        self.ip_input.setPlaceholderText("每行一个")
        self.ip_input.setFixedHeight(60)
        grid.addWidget(lbl_ip, row, 2)
        grid.addWidget(self.ip_input, row, 3)
        row += 1

        # 文件路径
        lbl_file = QLabel("文件路径(必需)：")
        self.filename_input = QTextEdit()
        self.filename_input.setPlaceholderText("每行一个")
        self.filename_input.setFixedHeight(60)
        grid.addWidget(lbl_file, row, 0)
        grid.addWidget(self.filename_input, row, 1, 1, 3)
        row += 1

        # 备用 hash 信息：MD5, SHA1, SHA256, Size；
        lbl_md5 = QLabel("MD5：")
        self.md5_input = QTextEdit()
        self.md5_input.setPlaceholderText("每行一个")
        self.md5_input.setFixedHeight(40)
        grid.addWidget(lbl_md5, row, 0)
        grid.addWidget(self.md5_input, row, 1)

        lbl_sha1 = QLabel("SHA1：")
        self.sha1_input = QTextEdit()
        self.sha1_input.setPlaceholderText("每行一个")
        self.sha1_input.setFixedHeight(40)
        grid.addWidget(lbl_sha1, row, 2)
        grid.addWidget(self.sha1_input, row, 3)
        row += 1

        lbl_sha256 = QLabel("SHA256：")
        self.sha256_input = QTextEdit()
        self.sha256_input.setPlaceholderText("每行一个")
        self.sha256_input.setFixedHeight(40)
        grid.addWidget(lbl_sha256, row, 0)
        grid.addWidget(self.sha256_input, row, 1)

        lbl_size = QLabel("Size(Bytes)：")
        self.size_input = QTextEdit()
        self.size_input.setPlaceholderText("每行一个")
        self.size_input.setFixedHeight(40)
        grid.addWidget(lbl_size, row, 2)
        grid.addWidget(self.size_input, row, 3)
        row += 1

        # Tags 部分
        lbl_tags = QLabel("Tags:")
        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("多个以逗号分隔，如: 攻击, APT")
        grid.addWidget(lbl_tags, row, 0)
        grid.addWidget(self.tag_input, row, 1, 1, 3)
        row += 1

        # 威胁等级
        lbl_threat = QLabel("威胁等级:")
        self.threat_level_combo = QComboBox()
        self.threat_level_combo.addItems(["1 - High", "2 - Medium", "3 - Low", "4 - Undefined"])
        default_threat = self.event_config.get("threat_level_id", "1")
        for i in range(self.threat_level_combo.count()):
            if self.threat_level_combo.itemText(i).startswith(default_threat):
                self.threat_level_combo.setCurrentIndex(i)
                break
        grid.addWidget(lbl_threat, row, 0)
        grid.addWidget(self.threat_level_combo, row, 1)
        row += 1

        # 新增复选框：是否检查重复事件
        self.chk_event_duplicate = QCheckBox("检查重复事件")
        self.chk_event_duplicate.setChecked(True)
        grid.addWidget(self.chk_event_duplicate, row, 1)
        row += 1

        # 上传按钮居中
        self.upload_btn = QPushButton("上传 Event")
        self.upload_btn.setStyleSheet(
            "QPushButton { font-size: 16px; padding: 12px 24px; background-color: #28A745; border-radius: 6px; color: #ffffff; }"
            "QPushButton:hover { background-color: #218838; }"
        )
        h_box = QHBoxLayout()
        h_box.addStretch(1)
        h_box.addWidget(self.upload_btn)
        h_box.addStretch(1)
        grid.addLayout(h_box, row, 0, 1, 4)

        self.upload_btn.clicked.connect(self.upload_event)
        self.setLayout(grid)
    
    def upload_event(self):
        duplicate_iocs = []  # 用于记录文本或样本层级的查重信息

        event_info = self.desc_input.toPlainText().strip()
        if not event_info:
            QMessageBox.warning(self, "错误", "请填写描述 (将作为事件 info)")
            return

        # --------------------------
        # 针对文本属性进行查重（attribute级别）
        attributes = []
        url_lines = [line.strip() for line in self.url_input.toPlainText().splitlines() if line.strip()]
        for url in url_lines:
            if not is_ioc_duplicate(self.misp, url):
                attributes.append({"type": "url", "value": url, "category": "Network activity"})
            else:
                duplicate_iocs.append(f"URL: {url}")
        ip_lines = [line.strip() for line in self.ip_input.toPlainText().splitlines() if line.strip()]
        for ip in ip_lines:
            if not is_ioc_duplicate(self.misp, ip):
                attributes.append({"type": "ip-dst", "value": ip, "category": "Network activity"})
            else:
                duplicate_iocs.append(f"IP: {ip}")

        # --------------------------
        # 处理文件样本进行查重（基于 SHA256 值）
        file_objects = []
        filename_lines = [line.strip() for line in self.filename_input.toPlainText().splitlines() if line.strip()]
        md5_lines = [line.strip() for line in self.md5_input.toPlainText().splitlines() if line.strip()]
        sha1_lines = [line.strip() for line in self.sha1_input.toPlainText().splitlines() if line.strip()]
        sha256_lines = [line.strip() for line in self.sha256_input.toPlainText().splitlines() if line.strip()]
        size_lines = [line.strip() for line in self.size_input.toPlainText().splitlines() if line.strip()]
        
        for i, file_path in enumerate(filename_lines):
            misp_file_obj = AbstractMISPObjectGenerator("file")
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                except Exception as e:
                    QMessageBox.warning(self, "错误", f"读取文件 {file_path} 失败: {str(e)}")
                    continue
                file_name = os.path.basename(file_path)
                md5_val = md5(file_content).hexdigest()
                sha1_val = sha1(file_content).hexdigest()
                sha256_val = sha256(file_content).hexdigest()
                size_val = len(file_content)
                # 针对文件样本先查重，根据 SHA256 值判断
                if is_ioc_duplicate(self.misp, sha256_val):
                    duplicate_iocs.append(f"样本: {file_name} (SHA256: {sha256_val})")
                    continue
                name_md5 = f"{file_name}|{md5_val}"
                misp_file_obj.add_attribute('malware-sample', value=name_md5, data=BytesIO(file_content))
                misp_file_obj.add_attribute('filename', value=file_name)
                misp_file_obj.add_attribute('md5', value=md5_val)
                misp_file_obj.add_attribute('sha1', value=sha1_val)
                misp_file_obj.add_attribute('sha256', value=sha256_val)
                misp_file_obj.add_attribute('size-in-bytes', value=size_val)
            else:
                file_name = file_path
                md5_val = md5_lines[i] if i < len(md5_lines) else ""
                sha1_val = sha1_lines[i] if i < len(sha1_lines) else ""
                sha256_val = sha256_lines[i] if i < len(sha256_lines) else ""
                size_val = size_lines[i] if i < len(size_lines) else ""
                misp_file_obj.add_attribute('filename', value=file_name)
                if md5_val:
                    misp_file_obj.add_attribute('md5', value=md5_val)
                if sha1_val:
                    misp_file_obj.add_attribute('sha1', value=sha1_val)
                if sha256_val:
                    misp_file_obj.add_attribute('sha256', value=sha256_val)
                if size_val:
                    misp_file_obj.add_attribute('size-in-bytes', value=size_val)
            file_obj = misp_file_obj.to_dict()
            file_objects.append(file_obj)

        # 如果有重复 IOC 属性，则统一弹窗显示
        if duplicate_iocs:
            dup_message = "下列 IOC 数据已存在（attribute级别重复），系统将忽略这些重复项:\n\n" + "\n".join(duplicate_iocs)
            QMessageBox.information(self, "重复的 IOC", dup_message)

        # --------------------------
        # 如果启用事件级别查重，则对事件内所有 IOC 进行查询（逐个查询后去重）
        if self.chk_event_duplicate.isChecked():
            query_parameters = []
            # 收集文本属性 IOC
            for att in attributes:
                query_parameters.append(att.get("value"))
            # 收集文件样本的 SHA256 值
            for file_obj in file_objects:
                for att in file_obj.get("Attribute", []):
                    if att.get("name") == "sha256":
                        query_parameters.append(att.get("value"))
            query_parameters = list(set(query_parameters))
            dup_event_ids = {}
            for value in query_parameters:
                events_found = self.misp.search(value=value, controller="events", pythonify=True)
                if events_found:
                    if isinstance(events_found, list):
                        for e in events_found:
                            dup_event_ids[e.get("id")] = e
                    elif isinstance(events_found, dict) and "Event" in events_found:
                        e = events_found["Event"]
                        dup_event_ids[e.get("id")] = e
            if dup_event_ids:
                msg = "检测到以下重复事件：\n"
                for event in dup_event_ids.values():
                    msg += f"Event ID: {event.get('id')}, Info: {event.get('info')}\n"
                msg += "终止事件上传\n"
                QMessageBox.information(self, "重复事件", msg)
                return

        current_timestamp = str(int(time.time()))
        current_date = datetime.today().strftime("%Y-%m-%d")
        selected_threat = self.threat_level_combo.currentText().split(" - ")[0]
        self.event_config["threat_level_id"] = selected_threat
        
        event_payload = {
            "Event": {
                "info": event_info,
                "timestamp": current_timestamp,
                "attribute_count": str(len(attributes)),
                "analysis": self.event_config["analysis"],
                "date": current_date,
                "org_id": self.event_config["org_id"],
                "distribution": self.event_config["distribution"],
                "published": self.event_config["published"],
                "proposal_email_lock": self.event_config["proposal_email_lock"],
                "locked": self.event_config["locked"],
                "threat_level_id": selected_threat,
                "sharing_group_id": self.event_config["sharing_group_id"],
                "disable_correlation": self.event_config["disable_correlation"],
                "extends_uuid": self.event_config["extends_uuid"],
                "event_creator_email": self.event_config["event_creator_email"],
                "Attribute": attributes,
                "Object": file_objects
            }
        }
        
        try:
            result = self.misp.add_event(event_payload)
            if 'Event' in result:
                event_id = result["Event"]["id"]
                msg = f"Event 上传成功！Event ID: {event_id}"
                tag_str = self.tag_input.text().strip()
                if tag_str:
                    tags = [t.strip() for t in tag_str.split(",") if t.strip()]
                    update_event_tag(self.misp, event_id, tags)
                    msg += f"\n已添加 Tag: {', '.join(tags)}"
                QMessageBox.information(self, "成功", msg)
                push_event_to_misp(event_payload)
                upload_file()
                # 注意：未调用 self.accept() 使对话框保持打开状态
            else:
                QMessageBox.warning(self, "失败", f"Event 上传失败: {result}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"请求失败: {str(e)}")


# ------------------------------
# 事件查询对话框（改进：查询时返回 event id, info 以及匹配的 attribute 键值对）
class EventQueryDialog(QDialog):
    def __init__(self, misp, parent=None):
        super().__init__(parent)
        self.misp = misp
        self.setWindowTitle("IOC Match")
        self.setGeometry(500, 300, 600, 400)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("请输入搜索关键字（IOC）")
        form.addRow("关键字：", self.search_input)
        
        search_btn = QPushButton("查询")
        search_btn.clicked.connect(self.search_event)
        form.addRow(search_btn)
        
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        layout.addLayout(form)
        layout.addWidget(self.result_area)
        self.setLayout(layout)
    
    def search_event(self):
        ioc = self.search_input.text().strip()
        if not ioc:
            QMessageBox.warning(self, "错误", "请输入 IOC")
            return

        output = ""
        # 第一部分：查询 attribute 并按 event_id 分组
        group_attrs = {}
        try:
            attr_result = self.misp.search(controller="attributes", value=ioc, pythonify=True)
            if attr_result:
                for attr in attr_result:
                    event_id = str(attr.event_id)
                    group_attrs.setdefault(event_id, []).append(attr)
        except Exception as e:
            output += f"属性查询失败: {str(e)}\n"

        # 第二部分：查询事件
        try:
            event_result = self.misp.search(value=ioc, controller="events", pythonify=True)
            output += "----- Event查询结果 -----\n"
            events = []
            if event_result:
                if isinstance(event_result, list):
                    events = event_result
                elif isinstance(event_result, dict):
                    if "Event" in event_result:
                        events = [event_result["Event"]]
                    elif "response" in event_result:
                        events = event_result["response"]

                for event in events:
                    event_id = str(event.get("id", "未知"))
                    info = event.get("info", "")
                    line = f"Event ID: {event_id}, Info: {info}"
                    # 如果在属性查询中匹配到了该 event，则输出所有 attribute 的键值对
                    if event_id in group_attrs:
                        for attr in group_attrs[event_id]:
                            attr_type = attr.get("type", "未知")
                            attr_value = attr.get("value", "")
                            line += f", {attr_type}={attr_value}"
                    output += line + "\n"
            else:
                output += "未查询到相关事件。\n"
        except Exception as e:
            output += f"事件查询失败: {str(e)}\n"

        self.result_area.setPlainText(output)

class TagSearchDialog(QDialog):
    def __init__(self, misp, parent=None):
        super().__init__(parent)
        self.misp = misp
        self.setWindowTitle("Tag 搜索")
        self.setGeometry(500, 300, 600, 400)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()
        
        # 输入标签关键字
        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("请输入 Tag 关键字，例如 APT 或 攻击")
        form.addRow("Tag:", self.tag_input)
        
        search_btn = QPushButton("查询 Tag")
        search_btn.clicked.connect(self.search_tag)
        form.addRow(search_btn)
        
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        layout.addLayout(form)
        layout.addWidget(self.result_area)
        self.setLayout(layout)
    
    def search_tag(self):
        tag_keyword = self.tag_input.text().strip()
        if not tag_keyword:
            QMessageBox.warning(self, "错误", "请输入 Tag 关键字")
            return

        output = ""
        # 第一部分：根据 Tag 查询 attribute，并按 event_id 分组
        group_attrs = {}
        try:
            attr_result = self.misp.search(tag=tag_keyword, controller="attributes", pythonify=True)
            if attr_result:
                for attr in attr_result:
                    event_id = str(attr.event_id)
                    group_attrs.setdefault(event_id, []).append(attr)
        except Exception as e:
            output += f"属性查询失败: {str(e)}\n"

        # 第二部分：根据 Tag 查询事件
        try:
            event_result = self.misp.search(tag=tag_keyword, controller="events", pythonify=True)
            output += "----- Tag 查询结果 -----\n"
            events = []
            if event_result:
                if isinstance(event_result, list):
                    events = event_result
                elif isinstance(event_result, dict):
                    if "Event" in event_result:
                        events = [event_result["Event"]]
                    elif "response" in event_result:
                        events = event_result["response"]

                for event in events:
                    event_id = str(event.get("id", "未知"))
                    info = event.get("info", "")
                    line = f"Event ID: {event_id}, Info: {info}"
                    if event_id in group_attrs:
                        for attr in group_attrs[event_id]:
                            attr_type = attr.get("type", "未知")
                            attr_value = attr.get("value", "")
                            line += f", {attr_type}={attr_value}"
                    output += line + "\n"
            else:
                output += "未查询到相关事件。\n"
        except Exception as e:
            output += f"事件查询失败: {str(e)}\n"

        self.result_area.setPlainText(output)

# ------------------------------
# 主窗口
class IOCUploader(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = configparser.ConfigParser()
        self.config_file = "config.ini"
        self.load_config()         # 加载 API 配置
        self.load_event_config()   # 加载事件配置
        try:
            self.misp = PyMISP(self.api_url, self.api_key, False, 'json')
        except Exception as e:
            QMessageBox.critical(self, "错误", f"初始化 PyMISP 失败: {str(e)}")
            sys.exit(1)
        self.setWindowTitle("MISP 交互工具")
        self.setGeometry(300, 200, 800, 600)
        self.setStyleSheet(self.get_light_theme())
        self.init_ui()

    def load_config(self):
        self.config.read(self.config_file)
        if not self.config.has_section("MISP"):
            self.config.add_section("MISP")
        self.api_url = self.config.get("MISP", "api_url", fallback="https://your-misp-instance.com")
        self.api_key = self.config.get("MISP", "api_key", fallback="your-api-key")

    def load_event_config(self):
        if not self.config.has_section("Event"):
            self.config.add_section("Event")
        self.event_config = {}
        self.event_config["org_id"] = self.config.get("Event", "org_id", fallback="1")
        self.event_config["orgc_id"] = self.config.get("Event", "orgc_id", fallback="1")
        self.event_config["distribution"] = self.config.get("Event", "distribution", fallback="0")
        self.event_config["published"] = self.config.getboolean("Event", "published", fallback=False)
        self.event_config["analysis"] = self.config.get("Event", "analysis", fallback="0")
        self.event_config["proposal_email_lock"] = self.config.getboolean("Event", "proposal_email_lock", fallback=False)
        self.event_config["locked"] = self.config.getboolean("Event", "locked", fallback=False)
        self.event_config["threat_level_id"] = self.config.get("Event", "threat_level_id", fallback="1")
        self.event_config["sharing_group_id"] = self.config.get("Event", "sharing_group_id", fallback="1")
        self.event_config["extends_uuid"] = self.config.get("Event", "extends_uuid", fallback="")
        self.event_config["event_creator_email"] = self.config.get("Event", "event_creator_email", fallback="user@example.com")
        self.event_config["disable_correlation"] = self.config.getboolean("Event", "disable_correlation", fallback=False)

    def save_config(self):
        if not self.config.has_section("MISP"):
            self.config.add_section("MISP")
        self.config["MISP"] = {"api_url": self.api_url, "api_key": self.api_key}
        if not self.config.has_section("Event"):
            self.config.add_section("Event")
        for key, value in self.event_config.items():
            if isinstance(value, bool):
                self.config["Event"][key] = "true" if value else "false"
            else:
                self.config["Event"][key] = str(value)
        with open(self.config_file, "w") as configfile:
            self.config.write(configfile)

    def init_ui(self):
        menubar = self.menuBar()
        settings_menu = QMenu("设置", self)
        config_api_action = QAction("配置 API", self)
        config_api_action.triggered.connect(self.open_api_config_dialog)
        settings_menu.addAction(config_api_action)
        config_event_action = QAction("配置事件", self)
        config_event_action.triggered.connect(self.open_event_config_dialog)
        settings_menu.addAction(config_event_action)
        about_me_action = QAction("About Me", self)
        about_me_action.triggered.connect(self.open_about_me_dialog)
        settings_menu.addAction(about_me_action)
        menubar.addMenu(settings_menu)
        
        event_menu = QMenu("Event", self)
        upload_event_action = QAction("Event Upload", self)
        upload_event_action.triggered.connect(self.open_event_upload_dialog)
        event_menu.addAction(upload_event_action)
        query_event_action = QAction("IOC match", self)
        query_event_action.triggered.connect(self.open_event_query_dialog)
        event_menu.addAction(query_event_action)
        tag_search_action = QAction("Tag Search", self)
        tag_search_action.triggered.connect(self.open_tag_search_dialog)
        event_menu.addAction(tag_search_action)
        menubar.addMenu(event_menu)
        menubar.addMenu(event_menu)
        
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        ascii_str = (
            "___  ________ ___________    ___          _     _              _   \n"
            "|  \/  |_   _/  ___| ___ \  / _ \        (_)   | |            | |  \n"
            "| .  . | | | \ `--.| |_/ / / /_\ \___ ___ _ ___| |_ __ _ _ __ | |_ \n"
            "| |\/| | | |  `--. \  __/  |  _  / __/ __| / __| __/ _` | '_ \| __|\n"
            "| |  | |_| |_/\__/ / |     | | | \__ \__ \ \__ \ || (_| | | | | |_ \n"
            "\_|  |_/\___/\____/\_|     \_| |_/___/___/_|___/\__\__,_|_| |_|\__|\n"
        )

        ascii_label = QLabel(ascii_str)
        font = QFont("Courier New", 20)
        ascii_label.setFont(font)
        ascii_label.setWordWrap(False)
        ascii_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_label = QLabel("请选择菜单中的“Event”功能：Event Upload或IOC Match。")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        main_layout.addWidget(ascii_label, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(welcome_label, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(ascii_label)
        main_layout.addWidget(welcome_label)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def open_api_config_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("API 配置")
        dialog.setGeometry(350, 250, 400, 200)
        layout = QFormLayout()
        api_url_input = QLineEdit(self.api_url)
        api_key_input = QLineEdit(self.api_key)
        layout.addRow("API URL:", api_url_input)
        layout.addRow("API Key:", api_key_input)
        save_button = QPushButton("保存")
        save_button.clicked.connect(lambda: self.save_api_config(api_url_input, api_key_input, dialog))
        layout.addRow(save_button)
        dialog.setLayout(layout)
        dialog.exec()

    def save_api_config(self, api_url_input, api_key_input, dialog):
        self.api_url = api_url_input.text().strip()
        self.api_key = api_key_input.text().strip()
        self.save_config()
        try:
            self.misp = PyMISP(self.api_url, self.api_key, False, 'json')
        except Exception as e:
            QMessageBox.critical(self, "错误", f"初始化 PyMISP 失败: {str(e)}")
        dialog.accept()
        QMessageBox.information(self, "成功", "API 配置已保存！")

    def open_event_config_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("事件配置")
        dialog.setGeometry(400, 300, 500, 400)
        layout = QFormLayout()
        self.event_fields = {}
        for key in ["org_id", "orgc_id", "distribution", "published", "analysis",
                    "proposal_email_lock", "locked", "threat_level_id", "sharing_group_id",
                    "extends_uuid", "event_creator_email", "disable_correlation"]:
            le = QLineEdit(str(self.event_config.get(key, "")))
            self.event_fields[key] = le
            layout.addRow(f"{key}:", le)
        save_button = QPushButton("保存事件配置")
        save_button.clicked.connect(lambda: self.save_event_config_changes(dialog))
        layout.addRow(save_button)
        dialog.setLayout(layout)
        dialog.exec()

    def save_event_config_changes(self, dialog):
        for key, widget in self.event_fields.items():
            text = widget.text().strip()
            if key in ["published", "proposal_email_lock", "locked", "disable_correlation"]:
                self.event_config[key] = True if text.lower() == "true" else False
            else:
                self.event_config[key] = text
        dialog.accept()
        self.save_config()
        QMessageBox.information(self, "成功", "事件配置已保存！")

    def open_event_upload_dialog(self):
        dialog = EventUploadDialog(self.misp, self.event_config, self)
        dialog.exec()

    def open_event_query_dialog(self):
        dialog = EventQueryDialog(self.misp, self)
        dialog.exec()
    
    def open_tag_search_dialog(self):
        dialog = TagSearchDialog(self.misp, self)
        dialog.exec()

    def open_about_me_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("About Me")
        dialog.setGeometry(400, 300, 500, 330)
        
        # 使用 QVBoxLayout 布局更加适合显示多行说明文本
        layout = QVBoxLayout()

        # 关于我的信息，这里采用 HTML 格式显示
        about_text = """
        <h2>MISP 交互工具</h2>
        <p><strong>版本:</strong> 1.0.0</p>
        <p><strong>主要作用:</strong><br>
        &nbsp;&nbsp;&nbsp;&nbsp;本程序用于与 MISP 系统进行交互，提供事件上传、事件查询、IOC 数据查重及文件样本处理等功能。
        </p>
        <p><strong>支持的 MISP 版本:</strong><br>
        &nbsp;&nbsp;&nbsp;&nbsp;支持 MISP 2.5 版本。
        </p>
        <p><strong>说明:</strong><br>
        &nbsp;&nbsp;&nbsp;&nbsp;本工具基于 PyMISP 库开发，通过图形界面帮助用户直观管理和操作 MISP 数据。
        </p>
        """

        # 将文本显示在 QLabel 中，并允许自动换行
        label = QLabel(about_text)
        label.setWordWrap(True)
        
        layout.addWidget(label)
        
        # 添加一个关闭按钮
        close_button = QPushButton("关闭")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)
        
        dialog.setLayout(layout)
        dialog.exec()

    def get_light_theme(self):
        return """
            QWidget { 
                background-color: #FFFFFF; 
                color: #333333; 
            }
            QLabel { 
                font-size: 14px; 
            }
            QTextEdit, QLineEdit {
                background-color: #FFFFFF;
                color: #333333;
                border: 1px solid #CCCCCC;
                padding: 8px;
                border-radius: 4px;
            }
            QComboBox {
                background-color: #FFFFFF;
                color: #333333;
                border: 1px solid #CCCCCC;
                padding: 4px;
                border-radius: 4px;
            }
            QPushButton {
                background-color: #007BFF;
                color: #FFFFFF;
                font-size: 16px;
                padding: 12px 24px;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QMenuBar { 
                background-color: #F5F5F5;
                color: #333333; 
            }
            QMenu { 
                background-color: #FFFFFF;
                color: #333333; 
            }
        """


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IOCUploader()
    window.show()
    sys.exit(app.exec())
