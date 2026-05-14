# Proto Conventions
The project should always be written in Nim unless stated otherwise. Please follow the conventions in the .md files in .iron/conventions.

## UI guidelines

If given the prompt to create a UI without specifics, you are to create it with the nim-webui library, using vanilla javascript, html and css. The UI should adhere to the following principles.

## UI Maingrid

Most UIs should be have a Main-Grid as a base structure looking like this:

| Top-Menu    | Top-Menu     | Top-Menu    | Top-Menu   | Top-Menu    |
| Left-Panel  | Left-Drag    |Main-Content | Right-Drag | Right-Panel | 
| Bottom-Panel| Bottom-Panel |Bottom-Panel |Bottom-Panel|Bottom-Panel |

With the dynamic/optional layout (if no left and right panels are needed):
| Top-Menu    | Top-Menu     | Top-Menu    | Top-Menu   | Top-Menu    |
|  Main-Content | Main-Content|Main-Content |Main-Content|Main-Content | 
| Bottom-Panel| Bottom-Panel |Bottom-Panel |Bottom-Panel|Bottom-Panel |

And the layout of just having one panel in a collapsed state:
| Top-Menu    | Top-Menu     | Top-Menu    | Top-Menu   | Top-Menu    |
|  Main-Content | Main-Content|Main-Content |Main-Content|Right-PanelCollapsed| 
| Bottom-Panel| Bottom-Panel |Bottom-Panel |Bottom-Panel|Bottom-Panel |
that yields an extended panel with drag-area on press:
| Top-Menu    | Top-Menu     | Top-Menu    | Top-Menu   | Top-Menu    |
|  Main-Content | Main-Content|Main-Content |Right-Drag|Right-PanelExtended | 
| Bottom-Panel| Bottom-Panel |Bottom-Panel |Bottom-Panel|Bottom-Panel |

The Top-Menu should also be a grid that looks like this:

| Search-Bar | Menu-Buttons1 | Menu-Buttons2 | Menu-Button2 | Menu-Buttons2|

The Main-Content should always span across the all columns with the exception of the right two. Those should be occupied by the Right-Drag handle and the Right-PanelExtended. When pressing a button in the Right-PanelExtended, the cell will instead be occupied by Right-PanelCollapsed and its column width will change as well. The Right-Drag will be occupied by the Main-Content.

The same behaviour should be done for the Left-Panel, but the Left-Panel and its Left-Drag should not be implemented unless specifically prompted. These are optional.

The Main-Content will hold visualized data - as a grid-list, cards, graphs or similar. Which kinds to use depend on the data. For text-based data lists are the best, with column-wise meta-data. For visual data like images and videos a cards/thumbnail flexbox might be best. For mathematical datapoints (benchmarks, coordinates, etc) - specifically, when there are a certain amount of numbers grouped by some tag/attribute and these numbers are dependant on the progression of another value (time/volume etc.) then they should definitely be represented in graphs. And these graphs themselves should be contained in cards that fit themselves neatly together in a dashboard like style.

It is entirely possible for different Top-Menu buttons to link to Main-Contents with different visualizations based on the data that is being displayed in the respective Main-Content.

For some projects you may go with a left menu instead:
| Left-Menu | Main-Content|Main-Content |Main-Content|Main-Content |
| Left-Menu | Main-Content|Main-Content |Right-Drag|Right-PanelExtended | 
| Left-Menu | Main-Content|Main-Content |Main-Content|Main-Content |
Specifically those that are very text heavy - like docs/books.

## UI Loginscreen

If the app is profile based (most apps are) it should have a login screen.
The login screen should be a small grid in the middle with the following layout:

Login layout:
| Top-Menu | Top-Menu | Top-Menu |
| Profile  | Profile  | Profile  |
| Input    | Input    | Input    |
| Bottom-Menu | Bottom-Menu | Bottom-Menu |

The Top-Menu should be a grid like this:
|Register|Login|Recover|

With each button leading to another layout of the Login grid.
Register layout:
| Top-Menu | Top-Menu | Top-Menu |
| Input    | Input    | Input    |
| Input    | Input    | Input    |
| Bottom-Menu | Bottom-Menu | Bottom-Menu |
with the Input cells also containing a picture picker for the profile etc.

Recover layout:
| Top-Menu | Top-Menu | Top-Menu |
| Rec-Method| Rec-Method|Rec-Method|
| Rec-Method| Rec-Method|Rec-Method|
| Bottom-Menu | Bottom-Menu | Bottom-Menu |
with the Rec-Method being a list of methods by which the user can recover his account and which he can click to expand them (passphrase/email code/sms code or all of them together).

## Style

- Set padding and margin to 0 for all containers and use center aligning and justifying only. You may only use padding if a container has a lot of text inside it.
- Grid gaps should be kept to a minimum or left out entirely (0px - 5px).
- Use flexboxes only to display visual data, but not to display any menus.
- Set border-radius to 0px or close to 0px for all containers. If you do use rounded corners, use them on singular corners only as highlighting or use a very shallow rounded border as a general base (0.5px-2px).
- Make sure to align the scrollbars color to the rest of the UI theme colors.
- Elements should not have borders all-around borders by default. 
- Keep panels etc. "floating". 
- Use backdrop-filter blur of 5-10px for most elements.
- The background color of the body should be rather dark and a gradient. 
- The menus and main-content should have blurred backgrounds and comparable brighter colors than the body background.
- Dont give each element inside another element its own background - mark them with one-sided borders instead as seperate elements - or dont show them as seperated elements at all.
- Keep backgrounds of buttons etc flat unless they are being selected or similar. Background-gradients are reserved as attention grabbers only (and for the main body background)
- Increase the gaps and the outer margin of the main-grid to make everything feel more floaty.
- Make sure that the different menus/filters/sort buttons differ slightly in style.
- In general, go for hyper minimalistic/simplistic UI design and keep clutter and get rid of unnecessary text/explanations/descriptions of any kind.
- Keep backgrounds isolated only to buttons and items themselves!!! Their wrappers/parent containers should have invisible backgrounds!

## UI Theming

Define colors somewhere at a top level in the css and then reuse them strategically.

By default, use these colors:
#e632d7;
#ddeaf6;
#6dc7dd;
#4784ca;
rgba(165, 45, 115, 0.9);
Use white and black colors with high transparency and stark backdrop blur for the main content and the menus.

## UI Seperation and visibility

Create the following color definitions:
- `glue` colors that group elements by function/attribute (e.g.: menu/tags from data/elements) <- these should be used for backgrounds, shadows, small, one-sided borders
- `separator` colors that separate big chunks/parts of the menu from other parts ( e.g.: different sections in the main-content) <- these should be used for big straight lines between elements as borders for example.
- `recommendation` colors grab the users attention and guide him through the UI (e.g.: first-time setup/common settings) <- these should be used for badges or background colors/gradients with one end being transparent.
- `tiny` colors that highlight smaller parts of the UI, to make up for their size by color (e.g.: badges) <- these should be used for badges or font shadows
- `active` colors that highlight active/selected elements <- these should be used for font-colors and backgrounds. A common tactic is to invert the regular color. Though that might be a bit too aggressive in some cases.

Define these colors and their appliances in advance and then use them throughout the UI to guide the user strategically.

## Badges

Create the following badges by default:
- circle badge
- diamond badge
- square badge
- diamond with rounded left and right border radius
Additionally, color badges with multiple colors:
- one-sided border color
- background color
- font color (badges should only hold one character at most)

You do not have to use all of them.

## UI Clutter

Keep the displayed information minimal - do not use descriptions/titles in div-boxes. The place for them to exist should be as tooltips only.
The user should understand the purpose of any element by placement, coloring, markers and the actual information inside the panel only. 

## UI Strategy

Before you start writing the UI, identify these things:
- What kind of data will the user handle? (table-like data/json-like data/text/images/references to data/videos)
- Will the user handle multiple kinds of data? (then maybe each menu needs to have different visuals for teh data)
- How should it be displayed? (List/Grid/Cards)
- What are the main things that user wants to do with the data? (Read/Sort/Edit/Share/Share parts of it)
- Which parts of the data need to be read/edited/shared/sorted?
- Should these functions be implemented per data-element or activate for all elements simultaneously or both via different buttons? 
- Where should the buttons live?

## UI Functions

In general, for the data-elements, we decide between two different functions:
1. Functions that only effect one data-element (edit/tag)
2. Functions that effect multiple data-elements (sort/filter)

Functions that effect only one data-point/element should have their button located in a menu that is close to the element or on the element itself. Alternatively, if there is a section that specifically only exists to show a menu/details that are data-element specific, then these kinds of buttons can live their as well.

Functions that effect multiple data-elements should live in a space somewhere that is shared by all data-elements of the current main-content.

## UI Animations

Make sure there are simple hover animations and click animations with a 0.4s transition for all kinds of interactions.

## UI File Structure

The respective .js files should be split by functionality, such that they dont grow too big. Do the same for the .html and .css files.
Refactor when needed. 
Always create two nimble tasks for the UI - one so I can run it and one so I can build it for production/release.