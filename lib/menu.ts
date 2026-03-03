import { squareFetch } from "@/lib/square";

export type MenuSectionHint = "food" | "drink" | "other";
export type MenuSectionSource = "square-taxonomy" | "keyword-fallback" | "unknown";

export type NormalizedMenuItem = {
  id: string;
  name: string;
  description: string;
  price: string;
  category: string;
  displayCategory: string;
  tags: string[];
  sectionHint: MenuSectionHint;
  sectionSource: MenuSectionSource;
  squareCategoryName: string;
  sectionRank: number;
  categoryRank: number;
  itemRank: number;
};

type CatalogObject = Record<string, unknown>;

const MAX_PAGE_COUNT = 30;
const PAGE_LIMIT = 100;

const TAXONOMY_FOOD_KEYWORDS = [
  "pizza",
  "pizzas",
  "all food",
  "panini",
  "paninis",
  "salad",
  "salads",
  "appetizer",
  "appetizers",
  "entree",
  "entrees",
  "dessert",
  "desserts",
  "sandwich",
  "sandwiches",
  "starter",
  "starters",
  "food",
  "dish",
];

const TAXONOMY_DRINK_KEYWORDS = [
  "package",
  "draft beer",
  "draft wine",
  "mixed drinks",
  "beer",
  "wine",
  "cocktail",
  "cocktails",
  "drink",
  "drinks",
  "whiskey",
  "vodka",
  "tequila",
  "mezcal",
  "gin",
  "rum",
  "brandy",
  "cordials",
  "cordial",
  "non alch",
  "non-alch",
  "spirits",
  "draft",
  "soda",
  "coffee",
];

const NAME_FOOD_FALLBACK_KEYWORDS = [
  "burger",
  "fries",
  "wings",
  "sandwich",
  "panini",
  "salad",
  "appetizer",
  "dessert",
  "entree",
];

const NAME_DRINK_FALLBACK_KEYWORDS = [
  "beer",
  "wine",
  "cocktail",
  "margarita",
  "martini",
  "spritz",
  "vodka",
  "whiskey",
  "tequila",
  "mezcal",
  "gin",
  "rum",
  "soda",
  "seltzer",
  "draft",
];

const FOOD_CATEGORY_PRIORITY = [
  "Starters",
  "Appetizers",
  "Salads",
  "Paninis",
  "Pizzas",
  "Entrees",
  "Desserts",
  "Sides",
  "Extra Sauce",
];

const DRINK_CATEGORY_PRIORITY = [
  "Mixed Drinks",
  "Cocktails",
  "Draft Beer/Wine",
  "Package",
  "Package Wine",
  "Draft Wine",
  "Whiskey/Scotch",
  "Tequila/Mezcal",
  "Vodka",
  "Gin",
  "Rum",
  "Brandy/Cognac",
  "Cordials",
  "Non Alch",
];

const FOOD_ITEM_PRIORITY_KEYWORDS = [
  "starter",
  "appetizer",
  "salad",
  "panini",
  "pizza",
  "entree",
  "dessert",
  "sauce",
];

const DRINK_ITEM_PRIORITY_KEYWORDS = [
  "cocktail",
  "margarita",
  "martini",
  "draft",
  "beer",
  "wine",
  "whiskey",
  "tequila",
  "mezcal",
  "vodka",
  "gin",
  "rum",
  "brandy",
  "cordial",
  "non alch",
];

function trim(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.trim();
}

function asCatalogObject(value: unknown): CatalogObject {
  if (typeof value !== "object" || value === null) return {};
  return value as CatalogObject;
}

function formatPrice(cents: number): string {
  const dollars = Number(cents) / 100;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(Number.isFinite(dollars) ? dollars : 0);
}

function includesAny(haystack: string, keywords: string[]): boolean {
  return keywords.some((keyword) => haystack.includes(keyword));
}

function normalizeLabel(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[_-]/g, " ")
    .replace(/\s+/g, " ");
}

function titleCaseWords(raw: string): string {
  return raw
    .split(" ")
    .filter((part) => part.length > 0)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join(" ");
}

function canonicalCategoryLabel(raw: string): string {
  const normalized = normalizeLabel(raw);
  if (!normalized || normalized === "menu") return "";

  const aliases: Record<string, string> = {
    "all food": "Food",
    appetizers: "Appetizers",
    appetizer: "Appetizers",
    starters: "Starters",
    starter: "Starters",
    salads: "Salads",
    salad: "Salads",
    paninis: "Paninis",
    panini: "Paninis",
    pizzas: "Pizzas",
    pizza: "Pizzas",
    entrees: "Entrees",
    entree: "Entrees",
    desserts: "Desserts",
    dessert: "Desserts",
    sides: "Sides",
    "extra sauce": "Extra Sauce",
    "mixed drinks": "Mixed Drinks",
    cocktails: "Cocktails",
    cocktail: "Cocktails",
    "draft beer/wine": "Draft Beer/Wine",
    "draft beer wine": "Draft Beer/Wine",
    package: "Package",
    "package (hensley)": "Package",
    "package wine": "Package Wine",
    "draft wine": "Draft Wine",
    "whiskey/scotch": "Whiskey/Scotch",
    "tequila/mezcal": "Tequila/Mezcal",
    vodka: "Vodka",
    gin: "Gin",
    rum: "Rum",
    "brandy/cognac": "Brandy/Cognac",
    cordials: "Cordials",
    cordial: "Cordials",
    "non alch": "Non Alch",
    "non-alch": "Non Alch",
    merch: "Merch",
  };
  if (aliases[normalized]) {
    return aliases[normalized];
  }

  return titleCaseWords(normalized);
}

function strongestSquareTag(tags: string[], sectionHint: MenuSectionHint): string {
  const canonicalTags = Array.from(
    new Set(tags.map(canonicalCategoryLabel).filter((tag) => tag.length > 0))
  );
  if (canonicalTags.length === 0) {
    return sectionHint === "food"
      ? "Food"
      : sectionHint === "drink"
      ? "Drinks"
      : "Other";
  }

  const priority =
    sectionHint === "food"
      ? FOOD_CATEGORY_PRIORITY
      : sectionHint === "drink"
      ? DRINK_CATEGORY_PRIORITY
      : [];

  for (const preferred of priority) {
    const found = canonicalTags.find(
      (tag) => normalizeLabel(tag) === normalizeLabel(preferred)
    );
    if (found) {
      return found;
    }
  }

  return canonicalTags[0];
}

function sectionRankForHint(sectionHint: MenuSectionHint): number {
  switch (sectionHint) {
    case "food":
      return 0;
    case "drink":
      return 1;
    case "other":
      return 2;
  }
}

function categoryRankForLabel(
  sectionHint: MenuSectionHint,
  displayCategory: string
): number {
  const normalizedDisplay = normalizeLabel(displayCategory);
  const priorities =
    sectionHint === "food"
      ? FOOD_CATEGORY_PRIORITY
      : sectionHint === "drink"
      ? DRINK_CATEGORY_PRIORITY
      : [];
  for (let index = 0; index < priorities.length; index += 1) {
    if (normalizeLabel(priorities[index]) === normalizedDisplay) {
      return index;
    }
  }
  return priorities.length + 100;
}

function itemRankForName(sectionHint: MenuSectionHint, name: string): number {
  const normalizedName = normalizeLabel(name);
  const keywords =
    sectionHint === "food"
      ? FOOD_ITEM_PRIORITY_KEYWORDS
      : sectionHint === "drink"
      ? DRINK_ITEM_PRIORITY_KEYWORDS
      : [];
  for (let index = 0; index < keywords.length; index += 1) {
    if (normalizedName.includes(keywords[index])) {
      return index;
    }
  }
  return keywords.length + 100;
}

function classifySection(
  category: string,
  name: string,
  tags: string[]
): { sectionHint: MenuSectionHint; sectionSource: MenuSectionSource } {
  const taxonomyHaystack = [category, ...tags].join(" ").toLowerCase();
  if (includesAny(taxonomyHaystack, TAXONOMY_DRINK_KEYWORDS)) {
    return { sectionHint: "drink", sectionSource: "square-taxonomy" };
  }
  if (includesAny(taxonomyHaystack, TAXONOMY_FOOD_KEYWORDS)) {
    return { sectionHint: "food", sectionSource: "square-taxonomy" };
  }

  const nameHaystack = name.toLowerCase();
  if (includesAny(nameHaystack, NAME_DRINK_FALLBACK_KEYWORDS)) {
    return { sectionHint: "drink", sectionSource: "keyword-fallback" };
  }
  if (includesAny(nameHaystack, NAME_FOOD_FALLBACK_KEYWORDS)) {
    return { sectionHint: "food", sectionSource: "keyword-fallback" };
  }

  return { sectionHint: "other", sectionSource: "unknown" };
}

function extractItemPrice(itemData: CatalogObject): string {
  const variations = Array.isArray(itemData.variations) ? itemData.variations : [];
  const cents = variations
    .map((variation) => {
      const variationData = asCatalogObject(variation);
      const itemVariationData = asCatalogObject(variationData.item_variation_data);
      const priceMoney = asCatalogObject(itemVariationData.price_money);
      return priceMoney.amount;
    })
    .filter(
      (value: unknown): value is number =>
        typeof value === "number" && Number.isFinite(value)
    )
    .map((value) => Math.max(0, Math.floor(value)));

  if (cents.length === 0) return "";
  return formatPrice(Math.min(...cents));
}

function normalizeCatalogItem(
  object: CatalogObject,
  categoryById: Map<string, string>
): NormalizedMenuItem | null {
  const id = trim(object.id);
  const itemData = asCatalogObject(object.item_data);
  const name = trim(itemData.name);
  if (!id || !name) return null;

  const categoryId = trim(itemData.category_id);
  const category = categoryById.get(categoryId) ?? "Menu";
  const description = trim(itemData.description);

  const tags: string[] = [category];
  if (Array.isArray(itemData.categories)) {
    for (const categoryRef of itemData.categories) {
      const categoryRefData = asCatalogObject(categoryRef);
      const relatedCategoryId = trim(categoryRefData.id);
      const label = categoryById.get(relatedCategoryId);
      if (label) tags.push(label);
    }
  }

  const normalizedTags = Array.from(
    new Set(
      tags
        .map((tag) => trim(tag))
        .filter((tag) => tag.length > 0)
    )
  );

  const classification = classifySection(category, name, normalizedTags);
  const displayCategory = strongestSquareTag(
    [category, ...normalizedTags],
    classification.sectionHint
  );
  const categoryRank = categoryRankForLabel(
    classification.sectionHint,
    displayCategory
  );
  const sectionRank = sectionRankForHint(classification.sectionHint);
  const itemRank = itemRankForName(classification.sectionHint, name);

  return {
    id,
    name,
    description,
    price: extractItemPrice(itemData),
    category: displayCategory,
    displayCategory,
    tags: normalizedTags,
    sectionHint: classification.sectionHint,
    sectionSource: classification.sectionSource,
    squareCategoryName: category,
    sectionRank,
    categoryRank,
    itemRank,
  };
}

async function fetchCatalogPage(cursor?: string) {
  const query = new URLSearchParams({
    types: "ITEM,CATEGORY",
    limit: String(PAGE_LIMIT),
  });
  if (cursor) query.set("cursor", cursor);

  return squareFetch(`/v2/catalog/list?${query.toString()}`, { method: "GET" });
}

async function fetchCatalogObjects() {
  const objects: CatalogObject[] = [];
  let cursor: string | undefined;

  for (let page = 0; page < MAX_PAGE_COUNT; page += 1) {
    const result = await fetchCatalogPage(cursor);
    if (!result.ok) {
      return {
        ok: false as const,
        error: result.error,
      };
    }

    const pageObjects = Array.isArray(result.data?.objects) ? result.data.objects : [];
    objects.push(...pageObjects);

    const nextCursor = trim(result.data?.cursor);
    if (!nextCursor) break;
    cursor = nextCursor;
  }

  return {
    ok: true as const,
    objects,
  };
}

export async function fetchNormalizedSquareMenu() {
  const catalog = await fetchCatalogObjects();
  if (!catalog.ok) {
    return {
      ok: false as const,
      error: catalog.error,
    };
  }

  const categoryById = new Map<string, string>();
  const items: NormalizedMenuItem[] = [];

  for (const object of catalog.objects) {
    const type = trim(object.type).toUpperCase();
    if (type === "CATEGORY") {
      const id = trim(object.id);
      const categoryData = asCatalogObject(object.category_data);
      const label = trim(categoryData.name);
      if (id && label) categoryById.set(id, label);
    }
  }

  for (const object of catalog.objects) {
    const type = trim(object.type).toUpperCase();
    if (type !== "ITEM") continue;
    const normalized = normalizeCatalogItem(object, categoryById);
    if (normalized) items.push(normalized);
  }

  const dedupedById = new Map<string, NormalizedMenuItem>();
  for (const item of items) dedupedById.set(item.id, item);

  const sortedItems = Array.from(dedupedById.values()).sort((a, b) => {
    if (a.sectionRank !== b.sectionRank) {
      return a.sectionRank - b.sectionRank;
    }
    if (a.categoryRank !== b.categoryRank) {
      return a.categoryRank - b.categoryRank;
    }
    if (a.displayCategory !== b.displayCategory) {
      return a.displayCategory.localeCompare(b.displayCategory);
    }
    if (a.itemRank !== b.itemRank) {
      return a.itemRank - b.itemRank;
    }
    return a.name.localeCompare(b.name);
  });

  return {
    ok: true as const,
    data: {
      source: "square",
      generatedAt: new Date().toISOString(),
      items: sortedItems,
    },
  };
}
