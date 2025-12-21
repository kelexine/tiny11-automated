#!/usr/bin/env python3
"""
Discord Notification System for Tiny11 Builds
Author: kelexine (https://github.com/kelexine)
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional

class DiscordNotifier:
    """Send rich notifications to Discord via webhooks"""
    
    COLORS = {
        'success': 0x00FF00,  # Green
        'error': 0xFF0000,    # Red
        'info': 0x3498DB,     # Blue
        'warning': 0xFFA500,  # Orange
        'release': 0x9B59B6   # Purple
    }
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_embed(
        self,
        title: str,
        description: str,
        color: str = 'info',
        fields: Optional[List[Dict]] = None,
        thumbnail: Optional[str] = None,
        image: Optional[str] = None
    ) -> bool:
        """Send a rich embed message to Discord"""
        
        embed = {
            'title': title,
            'description': description,
            'color': self.COLORS.get(color, self.COLORS['info']),
            'timestamp': datetime.utcnow().isoformat(),
            'footer': {
                'text': 'Tiny11 Automated Builder • kelexine',
                'icon_url': 'https://avatars.githubusercontent.com/u/YOUR_USER_ID'
            }
        }
        
        if fields:
            embed['fields'] = fields
        
        if thumbnail:
            embed['thumbnail'] = {'url': thumbnail}
        
        if image:
            embed['image'] = {'url': image}
        
        payload = {
            'username': 'Tiny11 Builder',
            'avatar_url': 'https://raw.githubusercontent.com/kelexine/tiny11-automated/main/.github/assets/bot-avatar.png',
            'embeds': [embed]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"❌ Discord notification failed: {e}")
            return False
    
    def notify_new_releases(self, releases: List[Dict]) -> bool:
        """Notify about newly detected Windows releases"""
        
        release_list = '\n'.join([
            f"• **{r['version']}** - Build {r['build_number']} ({r['title'][:50]}...)"
            for r in releases[:10]  # Limit to 10 for embed size
        ])
        
        if len(releases) > 10:
            release_list += f"\n... and {len(releases) - 10} more"
        
        fields = [
            {
                'name': '📦 Detected Releases',
                'value': release_list,
                'inline': False
            },
            {
                'name': '🏗️ Builds Queued',
                'value': f'{len(releases) * 6} total builds (Standard, Core, Nano × Home, Pro)',
                'inline': True
            },
            {
                'name': '⏱️ Estimated Time',
                'value': f'~{len(releases) * 30}-{len(releases) * 80} minutes',
                'inline': True
            }
        ]
        
        return self.send_embed(
            title='🆕 New Windows Releases Detected!',
            description=f'Found **{len(releases)}** new Windows 11 build(s) ready for processing.',
            color='release',
            fields=fields,
            thumbnail='https://upload.wikimedia.org/wikipedia/commons/e/e6/Windows_11_logo.svg'
        )
    
    def notify_build_started(
        self,
        version: str,
        build_type: str,
        edition: str
    ) -> bool:
        """Notify when a build job starts"""
        
        fields = [
            {'name': 'Version', 'value': version, 'inline': True},
            {'name': 'Type', 'value': build_type, 'inline': True},
            {'name': 'Edition', 'value': edition, 'inline': True}
        ]
        
        return self.send_embed(
            title='🏗️ Build Started',
            description=f'Starting {build_type} build for Windows {version} ({edition})',
            color='info',
            fields=fields
        )
    
    def notify_build_completed(
        self,
        version: str,
        build_type: str,
        edition: str,
        duration: str,
        iso_size: str,
        download_url: Optional[str] = None
    ) -> bool:
        """Notify when a build completes successfully"""
        
        fields = [
            {'name': 'Version', 'value': version, 'inline': True},
            {'name': 'Type', 'value': build_type, 'inline': True},
            {'name': 'Edition', 'value': edition, 'inline': True},
            {'name': 'Duration', 'value': duration, 'inline': True},
            {'name': 'ISO Size', 'value': iso_size, 'inline': True},
            {'name': 'Status', 'value': '✅ Ready', 'inline': True}
        ]
        
        if download_url:
            fields.append({
                'name': '📥 Download',
                'value': f'[SourceForge]({download_url})',
                'inline': False
            })
        
        return self.send_embed(
            title='✅ Build Completed Successfully!',
            description=f'Tiny11 {build_type} for Windows {version} ({edition}) is ready!',
            color='success',
            fields=fields
        )
    
    def notify_build_failed(
        self,
        version: str,
        build_type: str,
        edition: str,
        error: str,
        logs_url: str
    ) -> bool:
        """Notify when a build fails"""
        
        fields = [
            {'name': 'Version', 'value': version, 'inline': True},
            {'name': 'Type', 'value': build_type, 'inline': True},
            {'name': 'Edition', 'value': edition, 'inline': True},
            {'name': 'Error', 'value': f'```{error[:500]}```', 'inline': False},
            {'name': '📋 Logs', 'value': f'[View Full Logs]({logs_url})', 'inline': False}
        ]
        
        return self.send_embed(
            title='❌ Build Failed',
            description=f'Build failed for Windows {version} ({build_type} - {edition})',
            color='error',
            fields=fields
        )
    
    def notify_daily_summary(
        self,
        checks_today: int,
        new_releases: int,
        builds_completed: int,
        builds_failed: int
    ) -> bool:
        """Send daily statistics summary"""
        
        fields = [
            {'name': '🔍 Checks Performed', 'value': str(checks_today), 'inline': True},
            {'name': '🆕 New Releases', 'value': str(new_releases), 'inline': True},
            {'name': '✅ Builds Completed', 'value': str(builds_completed), 'inline': True},
            {'name': '❌ Builds Failed', 'value': str(builds_failed), 'inline': True},
            {'name': '📊 Success Rate', 'value': f'{(builds_completed / max(builds_completed + builds_failed, 1)) * 100:.1f}%', 'inline': True},
            {'name': '⏰ Next Check', 'value': 'Tomorrow at 00:00 UTC', 'inline': True}
        ]
        
        return self.send_embed(
            title='📊 Daily Build Summary',
            description='Summary of today\'s automated build activity',
            color='info',
            fields=fields
        )


def main():
    """CLI interface for Discord notifications"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Send Discord notifications')
    parser.add_argument('--webhook', required=True, help='Discord webhook URL')
    parser.add_argument('--type', required=True, choices=[
        'new-releases', 'build-started', 'build-completed', 
        'build-failed', 'daily-summary'
    ])
    parser.add_argument('--data', help='JSON data for notification')
    
    args = parser.parse_args()
    
    notifier = DiscordNotifier(args.webhook)
    data = json.loads(args.data) if args.data else {}
    
    # Call appropriate notification method
    if args.type == 'new-releases':
        success = notifier.notify_new_releases(data.get('releases', []))
    elif args.type == 'build-started':
        success = notifier.notify_build_started(
            data['version'], data['build_type'], data['edition']
        )
    elif args.type == 'build-completed':
        success = notifier.notify_build_completed(
            data['version'], data['build_type'], data['edition'],
            data['duration'], data['iso_size'], data.get('download_url')
        )
    elif args.type == 'build-failed':
        success = notifier.notify_build_failed(
            data['version'], data['build_type'], data['edition'],
            data['error'], data['logs_url']
        )
    elif args.type == 'daily-summary':
        success = notifier.notify_daily_summary(
            data['checks_today'], data['new_releases'],
            data['builds_completed'], data['builds_failed']
        )
    else:
        print(f"Unknown notification type: {args.type}")
        return 1
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
