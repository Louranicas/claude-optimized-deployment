#!/usr/bin/env python3
"""
Video to Documentation Example
Convert technical video tutorials into searchable documentation
"""

import asyncio
import os
from pathlib import Path
from typing import Optional

from src.circle_of_experts import EnhancedExpertManager
from src.video_processing import VideoToDocumentationPipeline


async def process_video_tutorial(
    video_url: str,
    output_path: Optional[str] = None,
    use_claude_4: bool = True
) -> str:
    """
    Process a video tutorial and convert it to documentation.
    
    Args:
        video_url: YouTube URL or local video path
        output_path: Where to save the documentation (optional)
        use_claude_4: Whether to use Claude 4 models (requires API key)
    
    Returns:
        Generated documentation as markdown string
    """
    
    # Initialize expert manager
    manager = EnhancedExpertManager()
    
    # Select appropriate expert
    if use_claude_4 and os.getenv("ANTHROPIC_API_KEY"):
        expert_model = "claude-opus-4-20250514"
    else:
        # Fallback to Claude 3 or other available models
        expert_model = "claude-3-opus" if os.getenv("ANTHROPIC_API_KEY") else "ollama-mixtral"
    
    print(f"Using model: {expert_model}")
    
    # Initialize video processor
    pipeline = VideoToDocumentationPipeline(
        expert_manager=manager,
        model=expert_model
    )
    
    # Process video
    print(f"Processing video: {video_url}")
    print("This may take several minutes depending on video length...")
    
    try:
        documentation = await pipeline.process_video(
            video_url=video_url,
            chunk_duration=300,  # 5-minute chunks
            max_screenshots_per_chunk=15
        )
        
        # Save if path provided
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(documentation)
            print(f"Documentation saved to: {output_path}")
        
        return documentation
        
    except Exception as e:
        print(f"Error processing video: {e}")
        raise


async def estimate_processing_cost(video_url: str) -> dict:
    """
    Estimate the cost of processing a video before actually doing it.
    
    Args:
        video_url: YouTube URL or local video path
    
    Returns:
        Cost estimation dictionary
    """
    
    pipeline = VideoToDocumentationPipeline()
    
    # Get video duration
    duration_seconds = await pipeline.get_video_duration(video_url)
    duration_hours = duration_seconds / 3600
    
    # Calculate costs for different models
    costs = {
        'claude_4_opus': {
            'model': 'Claude 4 Opus',
            'cost': calculate_claude_cost(duration_hours, model='opus-4'),
            'quality': 'Highest quality, extended thinking',
            'speed': 'Slower (10-30 min for 2hr video)'
        },
        'claude_3_opus': {
            'model': 'Claude 3 Opus',
            'cost': calculate_claude_cost(duration_hours, model='opus-3'),
            'quality': 'High quality',
            'speed': 'Moderate (20-30 min for 2hr video)'
        },
        'gpt_4': {
            'model': 'GPT-4',
            'cost': calculate_gpt_cost(duration_hours),
            'quality': 'Good quality',
            'speed': 'Moderate'
        },
        'local_llm': {
            'model': 'Ollama (Local)',
            'cost': 0,
            'quality': 'Basic quality',
            'speed': 'Slow (depends on hardware)'
        }
    }
    
    return {
        'video_duration': f"{duration_hours:.1f} hours",
        'estimated_chunks': int(duration_hours * 12),  # 5-min chunks
        'model_costs': costs,
        'recommendation': get_cost_recommendation(costs, duration_hours)
    }


def calculate_claude_cost(duration_hours: float, model: str = 'opus-3') -> float:
    """Calculate Claude API costs for video processing"""
    
    # Pricing per million tokens (as of May 2025)
    pricing = {
        'opus-4': {'input': 15, 'output': 75},
        'opus-3': {'input': 15, 'output': 75},
        'sonnet-3': {'input': 3, 'output': 15},
        'haiku-3': {'input': 0.25, 'output': 1.25}
    }
    
    # Estimate tokens
    chunks_per_hour = 12  # 5-minute chunks
    tokens_per_chunk = {
        'text': 1000,
        'images': 12000,  # 10 images @ 1.2k tokens each
        'output': 1000
    }
    
    total_chunks = duration_hours * chunks_per_hour
    input_tokens = total_chunks * (tokens_per_chunk['text'] + tokens_per_chunk['images'])
    output_tokens = total_chunks * tokens_per_chunk['output']
    
    # Calculate cost
    model_pricing = pricing.get(model, pricing['opus-3'])
    input_cost = (input_tokens / 1_000_000) * model_pricing['input']
    output_cost = (output_tokens / 1_000_000) * model_pricing['output']
    
    return round(input_cost + output_cost, 2)


def calculate_gpt_cost(duration_hours: float) -> float:
    """Calculate GPT-4 API costs for video processing"""
    
    # Similar calculation for GPT-4
    # Adjust based on current OpenAI pricing
    return round(duration_hours * 3.5, 2)  # Rough estimate


def get_cost_recommendation(costs: dict, duration_hours: float) -> str:
    """Get recommendation based on video length and budget"""
    
    if duration_hours < 0.5:
        return "For short videos (<30 min), Claude 4 Opus provides best quality at reasonable cost."
    elif duration_hours < 2:
        return "For medium videos (30 min - 2 hrs), Claude 3 Opus offers good balance of quality and cost."
    else:
        return "For long videos (>2 hrs), consider using Claude 3 Sonnet or processing in sections."


async def main():
    """Example usage of video processing"""
    
    # Example 1: Process a YouTube tutorial
    youtube_url = "https://www.youtube.com/watch?v=example_id"
    
    # First, estimate cost
    print("Estimating processing cost...")
    cost_estimate = await estimate_processing_cost(youtube_url)
    
    print("\nCost Estimation:")
    print(f"Video Duration: {cost_estimate['video_duration']}")
    print(f"Estimated Chunks: {cost_estimate['estimated_chunks']}")
    print("\nModel Options:")
    
    for model_id, info in cost_estimate['model_costs'].items():
        print(f"\n{info['model']}:")
        print(f"  Cost: ${info['cost']}")
        print(f"  Quality: {info['quality']}")
        print(f"  Speed: {info['speed']}")
    
    print(f"\nRecommendation: {cost_estimate['recommendation']}")
    
    # Example 2: Process with user confirmation
    user_input = input("\nProceed with processing? (y/n): ")
    
    if user_input.lower() == 'y':
        # Process the video
        documentation = await process_video_tutorial(
            video_url=youtube_url,
            output_path="output/tutorial_documentation.md",
            use_claude_4=True
        )
        
        print(f"\nDocumentation generated successfully!")
        print(f"Length: {len(documentation)} characters")
        
        # Example 3: Extract code examples
        from src.utils.code_extractor import extract_code_blocks
        
        code_blocks = extract_code_blocks(documentation)
        print(f"\nExtracted {len(code_blocks)} code examples")
        
        # Save code examples separately
        for i, code_block in enumerate(code_blocks):
            filename = f"output/code_examples/example_{i+1}.{code_block['language']}"
            Path(filename).parent.mkdir(parents=True, exist_ok=True)
            with open(filename, 'w') as f:
                f.write(code_block['code'])
        
        print(f"Code examples saved to output/code_examples/")


# Batch processing example
async def batch_process_course(playlist_url: str, course_name: str):
    """Process an entire course playlist"""
    
    from src.video_processing import get_playlist_videos
    
    # Get all videos in playlist
    videos = await get_playlist_videos(playlist_url)
    print(f"Found {len(videos)} videos in playlist")
    
    # Create course directory
    course_dir = Path(f"output/courses/{course_name}")
    course_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each video
    for i, video in enumerate(videos, 1):
        print(f"\nProcessing video {i}/{len(videos)}: {video['title']}")
        
        output_file = course_dir / f"{i:02d}_{video['safe_title']}.md"
        
        try:
            await process_video_tutorial(
                video_url=video['url'],
                output_path=str(output_file)
            )
        except Exception as e:
            print(f"Error processing {video['title']}: {e}")
            continue
    
    # Generate course index
    print("\nGenerating course index...")
    await generate_course_index(course_dir, course_name)


async def generate_course_index(course_dir: Path, course_name: str):
    """Generate an index file for the course"""
    
    index_content = f"# {course_name} - Course Documentation\n\n"
    index_content += "Generated from video tutorials using Claude AI\n\n"
    index_content += "## Table of Contents\n\n"
    
    # List all markdown files
    for md_file in sorted(course_dir.glob("*.md")):
        if md_file.name != "index.md":
            title = md_file.stem.replace('_', ' ').title()
            index_content += f"- [{title}]({md_file.name})\n"
    
    # Save index
    with open(course_dir / "index.md", 'w') as f:
        f.write(index_content)
    
    print(f"Course index saved to {course_dir / 'index.md'}")


if __name__ == "__main__":
    # Run the example
    asyncio.run(main())
    
    # Uncomment to batch process a course
    # asyncio.run(batch_process_course(
    #     playlist_url="https://www.youtube.com/playlist?list=...",
    #     course_name="kubernetes_mastery"
    # ))
