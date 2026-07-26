//! Cookbook-demo assembly (#201): the recipe equivalent of [`crate::crew`]. Turns the role agents'
//! JSON fragments into the `{safety, auction, recipe}` response the cookbook browser
//! (`POST /cookbook/build`) expects — same crew pattern as flappy-demo, new domain (recipe from a
//! fridge photo + text instead of a game from a prompt).
//!
//! This is the **pure core** (field-mapping + wire contract), decoupled from I/O. The role handlers
//! feed their fragment JSON in and the streaming bridge serializes the output straight back:
//!   * **source-2** (structure) emits an [`IngredientsFragment`]:
//!     `{ingredients, steps, cookTime, difficulty, allergens}` — ingredient recognition + recipe logic.
//!   * **sink** (presentation) emits a [`RecipeFragment`]:
//!     `{dishName, theme, garnish, moodDescription}` — naming/theming/plating.
//! The two merge into a [`RecipeCard`] the browser renders. `safety` (central) gates first, exactly
//! like the flappy `safety_check`. Wire field names are camelCase to match the browser directly.

use crate::crew::{RoleAuction, Safety};
use serde::{Deserialize, Serialize};

/// source-2's fragment — ingredient recognition + recipe structure (from the photo + text).
#[derive(Debug, Clone, Deserialize)]
pub struct IngredientsFragment {
    pub ingredients: Vec<String>,
    pub steps: Vec<String>,
    /// Human cook-time (e.g. `"35 minutes"`) — a string so the model isn't forced into a unit.
    #[serde(rename = "cookTime")]
    pub cook_time: String,
    pub difficulty: String,
    #[serde(default)]
    pub allergens: Vec<String>,
}

/// sink's fragment — naming / theming / plating over source-2's recipe.
#[derive(Debug, Clone, Deserialize)]
pub struct RecipeFragment {
    #[serde(rename = "dishName")]
    pub dish_name: String,
    pub theme: String,
    pub garnish: String,
    #[serde(rename = "moodDescription")]
    pub mood_description: String,
}

/// The assembled recipe card — serialized with the exact camelCase field names the cookbook page
/// reads (`dishName`, `cookTime`, `moodDescription`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeCard {
    #[serde(rename = "dishName")]
    pub dish_name: String,
    pub ingredients: Vec<String>,
    pub steps: Vec<String>,
    #[serde(rename = "cookTime")]
    pub cook_time: String,
    pub difficulty: String,
    pub allergens: Vec<String>,
    pub theme: String,
    pub garnish: String,
    #[serde(rename = "moodDescription")]
    pub mood_description: String,
}

impl RecipeCard {
    /// Merge the structure (source-2) + presentation (sink) fragments into the card. The dish name /
    /// theme / plating come from sink; the ingredients / steps / timing / allergens from source-2.
    pub fn from_fragments(structure: &IngredientsFragment, presentation: &RecipeFragment) -> Self {
        RecipeCard {
            dish_name: presentation.dish_name.clone(),
            ingredients: structure.ingredients.clone(),
            steps: structure.steps.clone(),
            cook_time: structure.cook_time.clone(),
            difficulty: structure.difficulty.clone(),
            allergens: structure.allergens.clone(),
            theme: presentation.theme.clone(),
            garnish: presentation.garnish.clone(),
            mood_description: presentation.mood_description.clone(),
        }
    }

    /// Parse the two fragment JSON blobs (as returned by the role handlers over the channel) and
    /// merge them. A malformed/missing-field fragment is a hard error (the bridge fails closed).
    pub fn from_fragment_json(structure_json: &str, presentation_json: &str) -> Result<Self, serde_json::Error> {
        let s: IngredientsFragment = serde_json::from_str(structure_json)?;
        let p: RecipeFragment = serde_json::from_str(presentation_json)?;
        Ok(Self::from_fragments(&s, &p))
    }
}

/// The cookbook `/cookbook/build` response: safety verdict + the visible auction + the assembled
/// recipe. Fail-closed exactly like [`crate::crew::CrewBuildResponse`]: a rejection omits the
/// auction + recipe entirely (a rejected prompt carries no recipe).
#[derive(Debug, Clone, Serialize)]
pub struct RecipeBuildResponse {
    pub safety: Safety,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auction: Option<Vec<RoleAuction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipe: Option<RecipeCard>,
}

impl RecipeBuildResponse {
    /// A safety rejection: the recipe is refused, nothing else is carried.
    pub fn rejected(reason: impl Into<String>) -> Self {
        RecipeBuildResponse { safety: Safety { ok: false, reason: reason.into() }, auction: None, recipe: None }
    }

    /// A clean build: the assembled recipe + the visible auction (who cooked each role).
    pub fn built(recipe: RecipeCard, auction: Vec<RoleAuction>) -> Self {
        RecipeBuildResponse { safety: Safety { ok: true, reason: String::new() }, auction: Some(auction), recipe: Some(recipe) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crew::RoleBid;

    #[test]
    fn recipe_fragments_map_to_card_and_response_is_failclosed() {
        // #201 (frozen): the cookbook assembly core — source-2's structure fragment + sink's
        // presentation fragment merge into a RecipeCard with the field names reconciled, serialized
        // camelCase for the browser; and the response is fail-closed on a rejection.
        let structure = r#"{"ingredients":["2 eggs","spinach","feta"],"steps":["whisk","fold","bake"],"cookTime":"25 minutes","difficulty":"easy","allergens":["egg","dairy"]}"#;
        let presentation = r#"{"dishName":"Green Shakshuka Bake","theme":"rustic","garnish":"chili oil + mint","moodDescription":"a sunny brunch for two"}"#;

        let card = RecipeCard::from_fragment_json(structure, presentation).expect("valid fragments parse");
        assert_eq!(card.dish_name, "Green Shakshuka Bake");
        assert_eq!(card.ingredients, vec!["2 eggs", "spinach", "feta"]);
        assert_eq!(card.steps.len(), 3);
        assert_eq!(card.cook_time, "25 minutes");
        assert_eq!(card.allergens, vec!["egg", "dairy"]);

        // Serializes with the camelCase names the cookbook page reads.
        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("\"dishName\":\"Green Shakshuka Bake\""), "dishName camelCase: {json}");
        assert!(json.contains("\"cookTime\":\"25 minutes\""), "cookTime camelCase");
        assert!(json.contains("\"moodDescription\":"), "moodDescription camelCase");

        // built() carries safety.ok + auction + recipe.
        let auction = vec![RoleAuction {
            role: "structure".into(),
            bids: vec![RoleBid { who: "source-2".into(), model: "claude-sonnet-5".into(), units: 20, price: 50, win: true }],
        }];
        let built = serde_json::to_value(RecipeBuildResponse::built(card.clone(), auction)).unwrap();
        assert_eq!(built["safety"]["ok"], serde_json::json!(true));
        assert_eq!(built["recipe"]["dishName"], serde_json::json!("Green Shakshuka Bake"));
        assert_eq!(built["auction"][0]["bids"][0]["who"], serde_json::json!("source-2"));

        // Fail-closed: a rejection omits auction + recipe (a rejected prompt carries no recipe).
        let rej = serde_json::to_value(RecipeBuildResponse::rejected("not a food request")).unwrap();
        assert_eq!(rej["safety"]["ok"], serde_json::json!(false));
        assert!(rej.get("recipe").is_none(), "no recipe on a rejection");
        assert!(rej.get("auction").is_none(), "no auction on a rejection");

        // A malformed fragment fails closed (Err), never a partial card.
        assert!(RecipeCard::from_fragment_json("{\"ingredients\":[]}", presentation).is_err(), "missing structure fields → Err");
        // allergens defaults to empty when the model omits it (not a hard error).
        let no_allergens = r#"{"ingredients":["rice"],"steps":["boil"],"cookTime":"10 minutes","difficulty":"easy"}"#;
        assert!(RecipeCard::from_fragment_json(no_allergens, presentation).unwrap().allergens.is_empty());
    }
}
