#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VISME Pro — Types, enums and configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
from collections import deque


APP_NAME = "VISME Pro"
APP_VERSION = "2.0.0"
DEFAULT_WIDTH = 1280
DEFAULT_HEIGHT = 720
DEFAULT_FPS = 30


class Mode(Enum):
    NONE = auto()
    DRAW = auto()
    ERASE = auto()
    TEXT = auto()
    BLAST = auto()
    LASER = auto()
    FACE_FILTERS = auto()
    HAND_GESTURES = auto()
    MIRROR = auto()
    POSTER = auto()
    VIRTUAL_PEN = auto()
    GESTURE_MOUSE = auto()
    STICKERS = auto()


class Effect(Enum):
    NORMAL = auto()
    GRAY = auto()
    SEPIA = auto()
    NEGATIVE = auto()
    CARTOON = auto()
    SKETCH = auto()
    EDGE = auto()
    PIXEL = auto()
    BLUR = auto()
    SHARPEN = auto()
    EMBOSS = auto()
    THERMAL = auto()
    MATRIX = auto()
    OIL_PAINT = auto()
    VIGNETTE = auto()
    HALFTONE = auto()
    CHROMATIC = auto()
    WAVE = auto()
    ASCII = auto()


class Sticker(Enum):
    GLASSES = auto()
    MUSTACHE = auto()
    HAT = auto()
    CROWN = auto()
    EARS = auto()


@dataclass
class AppConfig:
    width: int = DEFAULT_WIDTH
    height: int = DEFAULT_HEIGHT
    fps: int = DEFAULT_FPS
    camera_id: int = 0
    fullscreen: bool = False
    mirror: bool = True
    show_hud: bool = True
    show_help: bool = True
    record_path: str = ""
    snapshot_dir: str = "./visme_captures"
    no_mediapipe: bool = False
    debug: bool = False
    ascii_cols: int = 120
    gesture_mouse: bool = False
    virtual_pen: bool = False


@dataclass
class Brush:
    color: Tuple[int, int, int] = (0, 255, 0)
    size: int = 5
    mode: Mode = Mode.DRAW
    rainbow: bool = False
    hue: float = 0.0

    def next_rainbow(self) -> None:
        if not self.rainbow:
            return
        self.hue = (self.hue + 0.02) % 1.0
        import colorsys
        r, g, b = colorsys.hsv_to_rgb(self.hue, 1.0, 1.0)
        self.color = (int(b * 255), int(g * 255), int(r * 255))


@dataclass
class HandState:
    index_pos: Optional[Tuple[int, int]] = None
    thumb_pos: Optional[Tuple[int, int]] = None
    middle_pos: Optional[Tuple[int, int]] = None
    wrist_pos: Optional[Tuple[int, int]] = None
    is_pinching: bool = False
    is_fist: bool = False
    gesture: str = "none"
    handedness: str = "Unknown"


@dataclass
class FaceState:
    box: Optional[Tuple[int, int, int, int]] = None
    landmarks: List[Tuple[int, int]] = field(default_factory=list)
    yaw: float = 0.0
    pitch: float = 0.0
    roll: float = 0.0


@dataclass
class Particle:
    x: float = 0.0
    y: float = 0.0
    vx: float = 0.0
    vy: float = 0.0
    life: int = 60
    max_life: int = 60
    color: Tuple[int, int, int] = (0, 255, 0)
    size: int = 3

    def update(self) -> bool:
        self.x += self.vx
        self.y += self.vy
        self.vy += 0.4
        self.life -= 1
        return self.life > 0


@dataclass
class GestureCommand:
    name: str
    cooldown: float
    last_trigger: float = 0.0
    action: Optional[Callable[[], None]] = None

    def trigger(self) -> bool:
        now = __import__("time").time()
        if now - self.last_trigger < self.cooldown:
            return False
        self.last_trigger = now
        if self.action:
            self.action()
        return True
