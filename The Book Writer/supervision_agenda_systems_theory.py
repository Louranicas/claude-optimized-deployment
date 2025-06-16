#!/usr/bin/env python3
"""
Supervision Agenda and Systems Theory Case Study
Using Hyper-Narrative Synthor for Academic Writing
Target: 800 words, High Distinction criteria
Focus: Systems Theory in Mezzo Practice with Decolonising Approach
"""

import asyncio
from datetime import datetime
from pathlib import Path

# Import the Hyper-Narrative Synthor system
from hyper_narrative_synthor import HyperNarrativeSynthor, console

class SupervisionAgendaWriter:
    """Writer for supervision agenda and systems theory case study"""
    
    def __init__(self):
        self.target_words = 800
        self.title = "Monthly Supervision Agenda: Mezzo Practice Development"
        self.synthor = None
        
    async def initialize_synthor(self):
        """Initialize the Hyper-Narrative Synthor for academic supervision agenda"""
        
        self.synthor = HyperNarrativeSynthor(
            project_name="Supervision Agenda Systems Theory Case Study",
            genre="Academic/Professional Practice", 
            target_words=self.target_words
        )
        
        synopsis = """
        A supervision agenda for a community practice worker focusing on mezzo-level 
        group facilitation, including a detailed case study applying systems theory 
        through a decolonising and participatory lens. The agenda demonstrates 
        critical reflection, theoretical application, and practical examples from 
        working with community groups, supported by current scholarly literature.
        """
        
        await self.synthor.seed_synopsis(synopsis)
        
        outline = await self.synthor.generate_outline(4)
        
        console.print(f"[green]📋 Supervision agenda outline generated[/green]")
        
        return outline
        
    async def write_supervision_agenda(self) -> str:
        """Write the supervision agenda with systems theory case study"""
        
        console.print(f"[cyan]🚀 Beginning Supervision Agenda: {self.title}[/cyan]")
        
        await self.initialize_synthor()
        
        sections = [
            await self._write_agenda_header(),
            await self._write_agenda_items(),
            await self._write_case_study_introduction(),
            await self._write_systems_theory_application(),
            await self._write_decolonising_evaluation(),
            await self._write_references()
        ]
        
        full_document = "\n\n".join(sections)
        
        word_count = len(full_document.split())
        
        await self.synthor.save_snapshot(
            label="Supervision Agenda Complete",
            description=f"Completed supervision agenda with {word_count} words"
        )
        
        console.print(f"[green]✅ Supervision agenda completed with {word_count:,} words[/green]")
        
        return full_document
        
    async def _write_agenda_header(self) -> str:
        """Write agenda header and context"""
        
        return f"""# {self.title}

**Date:** {datetime.now().strftime('%B %d, %Y')}  
**Attendees:** Group Facilitator & Supervisor  
**Organisation:** Community Connections NGO  
**Role:** Mezzo Practice Group Facilitator  
**Duration:** 60 minutes

## Purpose
Monthly supervision to discuss group facilitation practice, professional development, and application of theoretical frameworks to community work."""

    async def _write_agenda_items(self) -> str:
        """Write prioritized agenda items"""
        
        return """## Agenda Items

### 1. Review of Group Programs (10 minutes)
• Update on current groups: Women's Support Circle, Youth Leadership Program, Elder's Storytelling Project
• Attendance patterns and engagement levels
• Emerging themes from participant feedback
• Resource allocation and venue considerations

### 2. Critical Incidents and Reflections (10 minutes)
• Discuss challenging group dynamics in Youth Leadership session
• Reflect on power dynamics observed in mixed-age community forum
• Strategies for managing conflict while maintaining participatory approach
• Self-care and professional boundaries in emotionally charged sessions

### 3. Partnership Development (10 minutes)
• Progress on collaboration with Indigenous Health Service
• Community capacity building initiatives with local schools
• Funding application for intergenerational program
• Stakeholder engagement strategy for upcoming community consultation

### 4. Professional Development (10 minutes)
• Decolonising practice workshop outcomes
• Application of participatory action research methods
• Training needs for trauma-informed group facilitation
• Supervision goals for next quarter

### 5. Systems Theory Case Study (20 minutes)
• Presentation of case study: "Applying Systems Theory to the Multicultural Women's Support Group"
• Discussion of theoretical application and practical outcomes
• Evaluation of decolonising and participatory approaches
• Implications for future practice"""

    async def _write_case_study_introduction(self) -> str:
        """Write case study introduction"""
        
        return """## Case Study: Systems Theory in the Multicultural Women's Support Group

### Context
The Multicultural Women's Support Group emerged from community consultations identifying isolation among newly arrived refugee and migrant women. Meeting weekly for two hours, the group includes 12-15 women from diverse cultural backgrounds including Syrian, Afghani, Sudanese, and Latin American communities. As facilitator, I applied systems theory to understand and work with the complex dynamics within this group."""

    async def _write_systems_theory_application(self) -> str:
        """Write detailed application of systems theory"""
        
        return """### Applying Systems Theory

Systems theory provided a framework for understanding the multiple interconnected systems affecting group members (Bronfenbrenner, 2005). Rather than viewing women's challenges as individual problems, I mapped the various systems impacting their lives:

**Microsystem interactions:** The group itself became a microsystem where women developed reciprocal relationships. I observed how trauma experiences from one member triggered responses in others, creating feedback loops that initially reinforced isolation patterns (Payne, 2014).

**Mesosystem connections:** By facilitating discussions about family-community interfaces, women identified how cultural expectations from their ethnic communities sometimes conflicted with Australian institutional requirements. This systems perspective helped normalize their struggles as systemic rather than personal failures (Healy, 2014).

**Exosystem influences:** We explored how immigration policies, employment systems, and educational institutions impacted members without their direct participation. One woman's experience navigating Centrelink illuminated how bureaucratic systems can perpetuate marginalization (Ife, 2013).

**Macrosystem considerations:** Cultural values, racism, and gender expectations emerged as powerful forces. The systems lens helped women see how patriarchal structures from both origin and host cultures intersected to limit their agency (Dominelli, 2018).

Through this framework, I designed interventions targeting multiple system levels. We created buddy systems (microsystem), organized family inclusion events (mesosystem), conducted advocacy training for institutional navigation (exosystem), and facilitated critical consciousness discussions about cultural and gender norms (macrosystem) (Teater, 2014)."""

    async def _write_decolonising_evaluation(self) -> str:
        """Write evaluation through decolonising lens"""
        
        return """### Evaluating Effectiveness Through a Decolonising Lens

The application of systems theory proved both valuable and problematic when evaluated through decolonising and participatory principles:

**Strengths:** Systems theory's holistic perspective aligned with many women's collectivist worldviews, contrasting with individualistic Western therapeutic approaches. It validated their emphasis on family and community interconnectedness. The framework supported participatory practice by positioning women as experts in their own systems (Tamburro, 2013).

**Limitations:** However, systems theory's Western academic origins required critical adaptation. The theory's tendency toward neutral analysis risked depoliticizing experiences of racism and colonial trauma. Women from Indigenous backgrounds particularly noted how systems theory could obscure power relations and historical injustices (Baskin, 2016).

**Participatory adaptations:** We collaboratively reconstructed the framework, incorporating Indigenous concepts of relationality and Middle Eastern understandings of family systems. Women created their own visual representations of their support systems using cultural symbols, moving beyond Western diagnostic models (Gray, Coates & Yellow Bird, 2013).

**Decolonising outcomes:** This approach fostered critical consciousness about how colonial systems perpetuate marginalization. Women began organizing collective responses to systemic barriers, transforming from service recipients to community advocates. The group evolved into a mutual aid network challenging traditional helper-client dynamics (Wehbi, 2018).

### Implications for Practice

This case demonstrates that while systems theory offers valuable insights for mezzo practice, its application must be critically examined through decolonising perspectives. Effective group work requires flexibility to adapt Western theories to diverse worldviews, genuine power-sharing in knowledge creation, and commitment to collective action against oppressive systems."""

    async def _write_references(self) -> str:
        """Write APA7 formatted references"""
        
        return """## References

Baskin, C. (2016). *Strong helpers' teachings: The value of Indigenous knowledges in the helping professions* (2nd ed.). Canadian Scholars' Press.

Bronfenbrenner, U. (2005). *Making human beings human: Bioecological perspectives on human development*. SAGE Publications.

Dominelli, L. (2018). *Anti-racist social work* (4th ed.). Red Globe Press.

Gray, M., Coates, J., & Yellow Bird, M. (Eds.). (2013). *Decolonizing social work*. Routledge.

Healy, K. (2014). *Social work theories in context: Creating frameworks for practice* (2nd ed.). Palgrave Macmillan.

Ife, J. (2013). *Community development in an uncertain world: Vision, analysis and practice*. Cambridge University Press.

Payne, M. (2014). *Modern social work theory* (4th ed.). Oxford University Press.

Tamburro, A. (2013). Including decolonization in social work education and practice. *Journal of Indigenous Social Development*, 2(1), 1-16.

Teater, B. (2014). *An introduction to applying social work theories and methods* (2nd ed.). Open University Press.

Wehbi, S. (2018). *Decolonizing and transforming international social work practice*. Routledge."""

    async def save_document(self, content: str) -> Path:
        """Save the document to file"""
        
        output_path = Path("Supervision_Agenda_Systems_Theory.md")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        export_path = await self.synthor.export("md", "academic")
        
        console.print(f"[green]💾 Document saved to: {output_path.absolute()}[/green]")
        console.print(f"[green]📤 Document exported to: {export_path}[/green]")
        
        return output_path

async def main():
    """Main execution function"""
    
    console.print("[bold cyan]🚀 Starting Supervision Agenda Generation[/bold cyan]")
    
    writer = SupervisionAgendaWriter()
    
    try:
        document_content = await writer.write_supervision_agenda()
        
        output_path = await writer.save_document(document_content)
        
        word_count = len(document_content.split())
        
        console.print(f"\n[bold green]✅ Supervision Agenda Generation Complete![/bold green]")
        console.print(f"[green]📊 Final word count: {word_count:,} words[/green]")
        console.print(f"[green]🎯 Target achieved: {'Yes' if 750 <= word_count <= 850 else 'Adjust needed'}[/green]")
        console.print(f"[green]📚 References included: 10 scholarly sources[/green]")
        console.print(f"[green]📁 Saved to: {output_path.absolute()}[/green]")
        
        return output_path
        
    except Exception as e:
        console.print(f"[red]❌ Error generating document: {e}[/red]")
        raise

if __name__ == "__main__":
    asyncio.run(main())