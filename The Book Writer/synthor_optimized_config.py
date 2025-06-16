#!/usr/bin/env python3
"""
Optimized Hyper-Narrative Synthor™ Configuration
Implements chunked generation, progress tracking, and timeout recovery
"""

import asyncio
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
import time
from pathlib import Path
import json

@dataclass
class SynthorConfig:
    """Enhanced configuration for Synthor system"""
    
    # Generation parameters
    chunk_size: int = 1200  # Words per chunk
    max_retries: int = 3
    timeout_seconds: int = 300
    auto_save_interval: int = 500  # Words
    
    # Progress tracking
    enable_progress: bool = True
    progress_callback: Optional[Callable] = None
    
    # Recovery options
    enable_checkpoints: bool = True
    checkpoint_dir: Path = Path(".synthor_checkpoints")
    
    # API optimization
    enable_streaming: bool = True
    batch_sections: bool = True
    parallel_generation: bool = False
    
    def __post_init__(self):
        """Ensure checkpoint directory exists"""
        if self.enable_checkpoints:
            self.checkpoint_dir.mkdir(exist_ok=True)


class OptimizedGenerationEngine:
    """Enhanced generation engine with timeout protection"""
    
    def __init__(self, config: SynthorConfig):
        self.config = config
        self.progress = {
            "total_words": 0,
            "completed_chunks": 0,
            "total_chunks": 0,
            "status": "initializing"
        }
        
    async def generate_with_chunks(
        self,
        sections: List[Dict],
        target_words: int
    ) -> str:
        """Generate content in chunks to avoid timeouts"""
        
        # Calculate total chunks needed
        self.progress["total_chunks"] = (target_words // self.config.chunk_size) + 1
        
        generated_content = []
        current_words = 0
        
        for i, section in enumerate(sections):
            print(f"\n📝 Generating section {i+1}/{len(sections)}: {section['title']}")
            
            section_content = ""
            section_target = section.get("word_budget", target_words // len(sections))
            
            while current_words < section_target:
                chunk_size = min(self.config.chunk_size, section_target - current_words)
                
                # Generate chunk with retry logic
                chunk = await self._generate_chunk_with_retry(
                    section=section,
                    chunk_size=chunk_size,
                    context=section_content
                )
                
                if chunk:
                    section_content += chunk
                    current_words += len(chunk.split())
                    self.progress["total_words"] = current_words
                    self.progress["completed_chunks"] += 1
                    
                    # Auto-save if enabled
                    if current_words % self.config.auto_save_interval < 50:
                        await self._auto_save(generated_content + [section_content])
                        
                    # Progress callback
                    if self.config.progress_callback:
                        self.config.progress_callback(self.progress)
                        
                else:
                    print(f"⚠️ Failed to generate chunk, moving to next section")
                    break
                    
            generated_content.append(section_content)
            
        return "\n\n".join(generated_content)
        
    async def _generate_chunk_with_retry(
        self,
        section: Dict,
        chunk_size: int,
        context: str
    ) -> Optional[str]:
        """Generate a single chunk with retry logic"""
        
        for attempt in range(self.config.max_retries):
            try:
                # Simulate chunk generation with timeout protection
                chunk = await asyncio.wait_for(
                    self._generate_chunk(section, chunk_size, context),
                    timeout=self.config.timeout_seconds
                )
                return chunk
                
            except asyncio.TimeoutError:
                print(f"⏱️ Timeout on attempt {attempt + 1}, retrying...")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
            except Exception as e:
                print(f"❌ Error on attempt {attempt + 1}: {e}")
                await asyncio.sleep(2 ** attempt)
                
        return None
        
    async def _generate_chunk(
        self,
        section: Dict,
        chunk_size: int,
        context: str
    ) -> str:
        """Generate a single chunk of content"""
        
        # Placeholder for actual generation logic
        # In production, this would call the API with streaming enabled
        
        prompt = f"""
        Continue writing section: {section['title']}
        Target: {chunk_size} words
        Context: {context[-500:] if context else 'Start of section'}
        Style: Scholarly, rigorous, with citations
        """
        
        # Simulate generation delay
        await asyncio.sleep(0.1)
        
        # Return sample content (in production, this would be API response)
        return f"Generated content for {section['title']} " * (chunk_size // 10)
        
    async def _auto_save(self, content_parts: List[str]):
        """Auto-save current progress"""
        
        if not self.config.enable_checkpoints:
            return
            
        checkpoint_file = self.config.checkpoint_dir / f"checkpoint_{int(time.time())}.json"
        
        checkpoint_data = {
            "timestamp": time.time(),
            "progress": self.progress,
            "content_parts": content_parts
        }
        
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f)
            
        # Clean old checkpoints (keep last 5)
        checkpoints = sorted(self.config.checkpoint_dir.glob("checkpoint_*.json"))
        for old_checkpoint in checkpoints[:-5]:
            old_checkpoint.unlink()


class EnhancedSynthorChapterWriter:
    """Enhanced chapter writer with optimization features"""
    
    def __init__(self, config: SynthorConfig):
        self.config = config
        self.engine = OptimizedGenerationEngine(config)
        
    async def write_chapter(
        self,
        title: str,
        sections: List[Dict],
        target_words: int = 8000
    ) -> str:
        """Write a complete chapter with optimizations"""
        
        print(f"🚀 Starting optimized generation for: {title}")
        print(f"📊 Target: {target_words:,} words")
        print(f"🔧 Chunk size: {self.config.chunk_size} words")
        print(f"⏱️ Timeout: {self.config.timeout_seconds} seconds")
        
        start_time = time.time()
        
        # Generate content with chunking
        content = await self.engine.generate_with_chunks(sections, target_words)
        
        # Add metadata
        metadata = f"""
---
Generated with Hyper-Narrative Synthor™ (Optimized)
Title: {title}
Word Count: {len(content.split())}
Generation Time: {time.time() - start_time:.2f} seconds
Chunks Used: {self.engine.progress['completed_chunks']}
---

"""
        
        return metadata + content
        
    def get_progress(self) -> Dict:
        """Get current generation progress"""
        return self.engine.progress


# Example usage function
async def demo_optimized_generation():
    """Demonstrate optimized generation"""
    
    # Create optimized configuration
    config = SynthorConfig(
        chunk_size=1000,
        max_retries=3,
        timeout_seconds=60,  # Shorter timeout for demo
        enable_progress=True,
        progress_callback=lambda p: print(f"📊 Progress: {p['total_words']:,} words ({p['completed_chunks']}/{p['total_chunks']} chunks)")
    )
    
    # Create writer
    writer = EnhancedSynthorChapterWriter(config)
    
    # Define chapter structure
    sections = [
        {"title": "Introduction", "word_budget": 1500},
        {"title": "Main Argument", "word_budget": 3000},
        {"title": "Evidence and Examples", "word_budget": 2500},
        {"title": "Conclusion", "word_budget": 1000}
    ]
    
    # Generate chapter
    chapter = await writer.write_chapter(
        title="Demo Chapter: Optimized Generation",
        sections=sections,
        target_words=8000
    )
    
    print(f"\n✅ Generation complete!")
    print(f"📊 Final word count: {len(chapter.split()):,}")
    
    return chapter


if __name__ == "__main__":
    # Run demo
    asyncio.run(demo_optimized_generation())