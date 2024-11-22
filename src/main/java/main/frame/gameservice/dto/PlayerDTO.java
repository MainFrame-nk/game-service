package main.frame.gameservice.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import main.frame.gameservice.model.BaseCard;
import main.frame.gameservice.model.characters.CharacterCard;
import main.frame.gameservice.model.characters.CompanionCard;
import main.frame.gameservice.model.effects.Ability;
import main.frame.gameservice.model.effects.Effect;
import main.frame.gameservice.model.equipment.BodyCard;
import main.frame.gameservice.model.equipment.HeadCard;
import main.frame.gameservice.model.equipment.LegCard;
import main.frame.gameservice.model.equipment.WeaponCard;

import java.util.List;
import java.util.Set;

@NoArgsConstructor
@Data
@Builder
@AllArgsConstructor
public class PlayerDTO {
    private Long id;
    private int level;
    private Set<CharacterCard> characterClasses;
    private int classesLimit;
    private Set<BaseCard> backpack;
    private int damage;
    private int companionLimit;
    private Set<CompanionCard> companions;
    private int weaponsLimit;
    private Set<WeaponCard> weapons;
    private List<Effect> buffs;
    private List<Effect> debuffs;
    private int handLimit = 6;
    private Set<BaseCard> hand;
    private Set<Ability> abilities;
    private HeadCard headSlot;
    private BodyCard bodySlot;
    private LegCard legSlot;
}