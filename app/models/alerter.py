import os
from telegram import Bot
from ..utils import load_config

class Alerting:
    def __init__(self):
        self.TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
        self.TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
        self.bot = Bot(token=self.TELEGRAM_BOT_TOKEN)

        
    async def send_alert(self, alert_name):
        """
        Send an alert message to the Telegram chat.
        """
        text = self.generate_alert_message(alert_name)
        async with self.bot:
            await self.bot.send_message(text=text, chat_id=self.TELEGRAM_CHAT_ID)

    def generate_alert_message(self, alert_name):
        # Define the smileys and emojis based on threat level
        threat_icon_labels = {
            0: ("ℹ️", "Informational"),
            1: ("😐", "Low"),
            2: ("⚠️", "Medium"),
            3: ("🟠", "High"),
            4: ("🔴", "Critical")
        }
        conf = load_config()
        threat_level= conf['IDS_settings']["ThreatLevels"][alert_name]
        if threat_level not in threat_icon_labels:
            raise ValueError("Invalid threat level. Must be 'low', 'medium', 'high', or 'critical'.")

        return f"🚨 Alert: {alert_name} detected 🚨\nThreat Level: {threat_icon_labels[threat_level][0]} {threat_icon_labels[threat_level][1]}\nAction: Immediate attention required."

